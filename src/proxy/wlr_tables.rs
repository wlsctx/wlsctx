//! Generated `&'static Interface` tables for the wlroots protocol family.
//!
//! The XMLs are vendored from the wlroots 0.20.2 source tree (see
//! `protocols/NOTICE`): this is the wlroots release that the sway on the
//! target system implements, and the published `wayland-protocols-wlr`
//! crate predates it (no input-method v2 / virtual-keyboard v1, and older
//! message sets for the `wlr-*` protocols).
//!
//! ## Layout
//!
//! Each protocol lives in its own private submodule. `wayland_scanner::generate_interfaces!`
//! always emits a batch of *private* C-interop helpers (`SyncWrapper`,
//! `types_null`, a `null` import) alongside the per-interface `pub static
//! {NAME}_INTERFACE`. Those helpers have fixed names, so calling the macro
//! several times in one module makes them collide (E0428/E0252). Splitting
//! each invocation into its own submodule scopes the helpers, and the
//! `pub use` below re-exports only the public `*_INTERFACE` statics (their
//! names are unique per interface, so the combined re-export is unambiguous).
//!
//! Cross-references to core interfaces (`wl_seat`, `wl_surface`, `wl_output`,
//! `wl_buffer`) and to `xdg_popup` (layer shell / foreign toplevels) are
//! resolved by the glob imports inside each submodule — the same imports the
//! upstream crates use. References *within* a protocol (e.g.
//! `zwlr_layer_surface_v1` from `zwlr_layer_shell_v1`) resolve inside the
//! submodule because both statics are emitted by the same macro invocation.

#![allow(dead_code, non_camel_case_types, missing_docs, unused_imports)]
pub mod __interfaces {
    mod drm {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/drm.xml");
    }
    mod input_method_v2 {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/input-method-unstable-v2.xml");
    }
    mod server_decoration {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/server-decoration.xml");
    }
    mod virtual_keyboard_v1 {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/virtual-keyboard-unstable-v1.xml");
    }
    mod wlr_data_control {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-data-control-unstable-v1.xml");
    }
    mod wlr_export_dmabuf {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-export-dmabuf-unstable-v1.xml");
    }
    mod wlr_foreign_toplevel {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!(
            "protocols/wlr-foreign-toplevel-management-unstable-v1.xml"
        );
    }
    mod wlr_gamma_control {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-gamma-control-unstable-v1.xml");
    }
    mod wlr_layer_shell {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-layer-shell-unstable-v1.xml");
    }
    mod wlr_output_management {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-output-management-unstable-v1.xml");
    }
    mod wlr_output_power_management {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!(
            "protocols/wlr-output-power-management-unstable-v1.xml"
        );
    }
    mod wlr_screencopy {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-screencopy-unstable-v1.xml");
    }
    mod wlr_virtual_pointer {
        use wayland_client::protocol::__interfaces::*;
        use wayland_protocols::xdg::shell::client::__interfaces::*;
        wayland_scanner::generate_interfaces!("protocols/wlr-virtual-pointer-unstable-v1.xml");
    }

    // Re-export the public `*_INTERFACE` statics (unique names, no collision).
    pub use drm::*;
    pub use input_method_v2::*;
    pub use server_decoration::*;
    pub use virtual_keyboard_v1::*;
    pub use wlr_data_control::*;
    pub use wlr_export_dmabuf::*;
    pub use wlr_foreign_toplevel::*;
    pub use wlr_gamma_control::*;
    pub use wlr_layer_shell::*;
    pub use wlr_output_management::*;
    pub use wlr_output_power_management::*;
    pub use wlr_screencopy::*;
    pub use wlr_virtual_pointer::*;
}
