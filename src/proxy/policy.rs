//! The proxy's global-allowlist policy (Phase 2).
//!
//! The compositor announces every global it has as `wl_registry.global`
//! events, and a client can `bind` any global *by name* — the compositor
//! creates the object regardless of whether the client ever saw the
//! announcement. Filtering the registry events alone therefore does not
//! hide a global from a determined client that can enumerate or guess
//! names. The proxy enforces the allowlist at both edges: it drops
//! `global`/`global_remove` events for interfaces that are not
//! allowlisted (so the client never learns of them) and rejects any
//! `bind` of a name it did not show, with a `wl_display.error`
//! (`invalid_object`) that fails the client closed.
//!
//! An *inactive* policy (the default, and what Phase 1 used) allows
//! every interface: the proxy is then a pure pass-through and behaves
//! exactly as the transparent relay.
//!
//! The allowlist is a set of *interface names* (e.g. `wl_compositor`,
//! `zwp_tablet_v1`), matched against the interface field of a `global`
//! event. Version and the numeric global name are not part of the match.

use std::collections::HashSet;
use std::fmt;

/// A global-allowlist policy.
#[derive(Clone)]
pub struct Policy {
    /// `None`: allow everything (the pass-through default).
    /// `Some(set)`: only interfaces in `set` are shown to clients.
    allowlist: Option<HashSet<String>>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.allowlist {
            None => f.debug_struct("Policy").field("mode", &"all").finish(),
            Some(set) => f
                .debug_struct("Policy")
                .field("mode", &"allowlist")
                .field("count", &set.len())
                .finish(),
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::all()
    }
}

impl Policy {
    /// The pass-through default: every interface is shown to clients.
    pub fn all() -> Self {
        Self { allowlist: None }
    }

    /// A policy that shows only the given interface names.
    pub fn from_names(names: impl IntoIterator<Item = String>) -> Self {
        Self { allowlist: Some(HashSet::from_iter(names)) }
    }

    /// Parse a comma-separated list of interface names (empty/blank
    /// entries are ignored) into a `from_names` policy.
    pub fn from_csv(csv: &str) -> Self {
        Self::from_names(
            csv.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        )
    }

    /// Whether the policy is active (i.e. actually filtering).
    pub fn is_active(&self) -> bool {
        self.allowlist.is_some()
    }

    /// Whether a global implementing `iface` should be shown to the
    /// client. Always `true` for an inactive (pass-through) policy.
    pub fn allows(&self, iface: &str) -> bool {
        match &self.allowlist {
            None => true,
            Some(set) => set.contains(iface),
        }
    }

    /// The number of allowlisted interfaces (0 for an inactive
    /// pass-through policy). For logging.
    pub fn allow_count(&self) -> usize {
        self.allowlist.as_ref().map_or(0, HashSet::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_policy_passes_everything() {
        let p = Policy::all();
        assert!(!p.is_active());
        assert!(p.allows("wl_compositor"));
        assert!(p.allows("zwp_totally_bogus_v99"));
    }

    #[test]
    fn allowlist_filters_by_interface_name() {
        let p = Policy::from_csv("wl_compositor, wl_shm ,zwp_tablet_v1,");
        assert!(p.is_active());
        assert!(p.allows("wl_compositor"));
        assert!(p.allows("wl_shm"));
        assert!(p.allows("zwp_tablet_v1"));
        assert!(!p.allows("wp_security_context_manager_v1"));
        assert!(!p.allows("wl_data_source"));
    }

    #[test]
    fn empty_csv_is_an_empty_allowlist_not_all() {
        // An explicitly empty allowlist hides everything; it is distinct
        // from the (no-flag) pass-through default.
        let p = Policy::from_csv("");
        assert!(p.is_active());
        assert!(!p.allows("wl_compositor"));
    }

    #[test]
    fn default_is_all() {
        let p = Policy::default();
        assert!(!p.is_active());
        assert!(p.allows("anything"));
    }
}
