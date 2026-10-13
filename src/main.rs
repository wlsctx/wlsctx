//! The wlsctx binary: tag-and-park (the default) or transparent
//! Wayland proxy (`--proxy`).

use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path;

use anyhow::{Context, Result, bail};
use clap::Parser;
use env_logger::Env;
use log::{Level, info, log_enabled};
use wayland_client::Connection;

/// Set up a Wayland socket with an attached security context, and
/// (optionally) relay sandboxed clients through it.
///
/// See https://wayland.app/protocols/security-context-v1 and the
/// library docs for the architecture.
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
struct Cli {
    /// Application ID in security context
    #[arg(long, env = "WLSCTX_APP_ID")]
    app_id: String,
    /// Instance ID in security context
    #[arg(long, env = "WLSCTX_INSTANCE_ID")]
    instance_id: String,
    /// Sandbox engine ID in security context
    #[arg(long, env = "WLSCTX_SANDBOX_ENGINE")]
    sandbox_engine: String,
    /// Listen on Unix socket
    #[arg(
        long,
        env = "WLSCTX_SOCKET_PATH",
        required_unless_present = "socket_activation"
    )]
    listen: Option<path::PathBuf>,
    /// Receive socket via systemd socket activation (LISTEN_FDS)
    #[arg(long, conflicts_with = "listen")]
    socket_activation: bool,
    /// Run as a transparent Wayland proxy: every connection to the
    /// listen socket is relayed to the compositor through a
    /// security-context connection to --tagged-socket, so the
    /// compositor applies per-context policy to the sandboxed client
    #[arg(long)]
    proxy: bool,
    /// (Proxy mode only) path of the tagged listener: bound here,
    /// passed to the compositor, and the only socket the proxy
    /// connects to upstream. It must be unreachable from the
    /// sandboxed app (e.g. the sidecar's private runtime dir)
    #[arg(long, required_if_eq("proxy", "true"))]
    tagged_socket: Option<path::PathBuf>,
    /// (Proxy mode only) comma-separated list of Wayland interface
    /// names the sandboxed app may bind. When set, the proxy hides
    /// every other global from the registry and rejects a bind of any
    /// name the app was never shown (a `wl_display.error`
    /// `invalid_object`); when unset the proxy is a pass-through and
    /// shows all globals (the Phase 1 behaviour)
    #[arg(
        long,
        env = "WLSCTX_ALLOW_GLOBALS",
        value_delimiter = ',',
        num_args = 1..,
        value_name = "INTERFACE"
    )]
    allow_globals: Vec<String>,
    /// (Proxy mode only) clipboard policy for the sandboxed apps:
    /// `allow` (the default) relays `wl_data_offer.receive` requests
    /// unchanged; `deny` relays a receive only when it reads data the
    /// app itself put on the clipboard — every other read is dropped
    /// silently (the app sees an empty clipboard; its own copy-and-
    /// paste keeps working). In both policies a receive whose fd is
    /// not an in-memory channel (memfd/pipe/socket) is a fatal
    /// protocol error: compositors do not inspect the fd they are
    /// handed, so the check is what stops an app from directing
    /// clipboard data into a file
    #[arg(
        long,
        env = "WLSCTX_CLIPBOARD_POLICY",
        default_value = "allow",
        value_name = "POLICY"
    )]
    clipboard_policy: String,
}

/// Validate the argument combinations clap cannot express
/// (`--tagged-socket` and `--allow-globals` are meaningless outside
/// `--proxy` mode).
fn validate(cli: &Cli) -> Result<()> {
    if !cli.proxy
        && let Some(p) = &cli.tagged_socket
    {
        bail!(
            "--tagged-socket ({p:?}) is only valid together with --proxy; \
             in tag-and-park mode the --listen socket itself is the tagged one"
        );
    }
    if !cli.proxy && !cli.allow_globals.is_empty() {
        bail!(
            "--allow-globals is only valid together with --proxy; \
             the tag-and-park mode has no relay to filter"
        );
    }
    let clipboard = wlsctx::proxy::ClipboardPolicy::parse(&cli.clipboard_policy)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !cli.proxy && clipboard != wlsctx::proxy::ClipboardPolicy::Allow {
        bail!(
            "--clipboard-policy {} is only valid together with --proxy; \
             the tag-and-park mode has no relay to filter",
            cli.clipboard_policy
        );
    }
    Ok(())
}

/// The main function of our program
fn main() -> Result<()> {
    let env = Env::default().default_filter_or("warn");
    env_logger::init_from_env(env);
    let cli = Cli::parse();
    validate(&cli)?;
    if cli.proxy {
        run_proxy(&cli)
    } else {
        run_tag_and_park(&cli)
    }
}

/// Tag-and-park (the current/default behaviour): tag the listen socket
/// with the security context, hold the reference pipe, park until
/// killed. Apps connect to the tagged socket directly.
fn run_tag_and_park(cli: &Cli) -> Result<()> {
    let (app_id, instance_id, listener) = obtain_listener(cli)?;

    if log_enabled!(Level::Info)
        && let Ok(local_addr) = listener.local_addr()
    {
        info!("Listening on {local_addr:?} (tagged)")
    }

    let conn = connect_to_compositor()?;
    let close_fd = wlsctx::security_context::create_security_context(
        conn,
        &listener,
        &cli.sandbox_engine,
        &app_id,
        &instance_id,
    )?;
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    wlsctx::proxy::run_signal_loop()?;
    info!("Shutting down.");
    Ok(())
}

/// Proxy mode: tag a *second*, private listener; every app connection
/// to the public socket is relayed to the compositor through a fresh
/// security-context connection to it.
fn run_proxy(cli: &Cli) -> Result<()> {
    let (app_id, instance_id, public) = obtain_listener(cli)?;
    let tagged_path = resolve_listener_path(cli.tagged_socket.as_deref().unwrap())?;
    let tagged = wlsctx::proxy::bind_listener(&tagged_path)
        .with_context(|| format!("binding the tagged listener {tagged_path:?}"))?;

    if log_enabled!(Level::Info)
        && let Ok(local_addr) = public.local_addr()
    {
        info!("Listening on {local_addr:?} (public); tagged listener at {tagged_path:?}")
    }

    let conn = connect_to_compositor()?;
    let close_fd = wlsctx::security_context::create_security_context(
        conn,
        &tagged,
        &cli.sandbox_engine,
        &app_id,
        &instance_id,
    )?;
    // The compositor now holds its own copy of the tagged listener and
    // accepts (and stamps) connections on it; the proxy only connects
    // to it by path. Dropping our copy guarantees we can never accept
    // on it (which would race the compositor and bypass the context).
    drop(tagged);
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

    let policy = wlsctx::proxy::Policy::from_names(cli.allow_globals.clone());
    if policy.is_active() {
        info!("Global allowlist active: showing {} interface(s) to sandboxed clients", policy.allow_count());
    } else {
        info!("No global allowlist: pass-through (all globals shown)");
    }
    let clipboard = wlsctx::proxy::ClipboardPolicy::parse(&cli.clipboard_policy)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if clipboard.is_active() {
        info!("Clipboard gate active (deny): sandboxed reads of foreign selections come back empty");
    } else {
        info!("Clipboard gate: pass-through (allow)");
    }
    info!("Clipboard fd sanity check is on in both policies (receive fds must be in-memory channels)");
    wlsctx::proxy::event_loop(&public, &tagged_path, &policy, clipboard, None)?;
    info!("Shutting down.");
    Ok(())
}

/// Connect to the host compositor, following the environment:
/// `WAYLAND_SOCKET` (fd-based; the in-pod sidecar receives the host
/// socket as its stdin, `WAYLAND_SOCKET=0`) takes precedence over
/// `WAYLAND_DISPLAY` (name-based; standalone mode mounts the host
/// socket into the container).
fn connect_to_compositor() -> Result<Connection> {
    Connection::connect_to_env().context(
        "connecting to the upstream Wayland compositor failed (NoCompositor); \
         check that WAYLAND_DISPLAY/WAYLAND_SOCKET reach the host compositor \
         (the wl-display@ sidecar passes the host wayland-1 socket via stdin, \
         wlsctx@ mounts it into the container)",
    )
}

/// Get the Unix listener to serve, either from a systemd socket
/// activation or by binding the socket ourselves. Returns
/// (app_id, instance_id, listener).
fn obtain_listener(cli: &Cli) -> Result<(String, String, UnixListener)> {
    let app_id = cli.app_id.clone();
    let instance_id = cli.instance_id.clone();
    if cli.socket_activation {
        // The IDs come from --app-id/--instance-id (or the
        // WLSCTX_APP_ID / WLSCTX_INSTANCE_ID environment variables). They
        // used to be derived from the fd name, but that only worked for
        // "app@instance" instance names and wlsctx@.socket sets
        // FileDescriptorName=%i, so the name normally contains no '@' and
        // the derivation panicked.
        match sd_notify::listen_fds_with_names(true).map(|mut it| it.next()) {
            Ok(Some((raw_fd, name))) => {
                info!("Received socket {name} ({raw_fd:#?}) from parent");
                // SAFETY: sd_notify::listen_fds_with_names(true) unsets the LISTEN_FDS variable so we should be
                // the only user of this fd
                let listener = unsafe { UnixListener::from_raw_fd(raw_fd) };
                Ok((app_id, instance_id, listener))
            }
            _ => bail!(
                "no socket was received via systemd socket activation (LISTEN_FDS is not set \
                 or empty); run wlsctx through the wlsctx@.socket unit or use --listen instead"
            ),
        }
    } else {
        let socket_path = cli.listen.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "--listen is required when --socket-activation is not set \
                 (or set WLSCTX_SOCKET_PATH)"
            )
        })?;
        let socket_abspath = resolve_listener_path(socket_path)?;
        let listener =
            wlsctx::proxy::bind_listener(&socket_abspath).with_context(|| {
                format!(
                    "binding {socket_abspath:?} failed (a stale socket could not be removed, \
                     or the path is not writable)"
                )
            })?;
        Ok((app_id, instance_id, listener))
    }
}

/// Resolve a `--listen`/`--tagged-socket` path: absolute paths are
/// used as-is; relative ones are placed in the runtime directory
/// (`XDG_RUNTIME_DIR`).
fn resolve_listener_path(p: &path::Path) -> Result<path::PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        xdg::BaseDirectories::new()
            .place_runtime_file(p)
            .with_context(|| {
                format!(
                    "placing {p:?} in the runtime directory \
                     (is XDG_RUNTIME_DIR set?)"
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // clap reads the process environment for its `env` attributes, and
    // tests run in parallel, so environment-mutating tests must be
    // serialised against each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Set (Some) or unset (None) the given environment variables for
    /// the duration of `f`, restoring whatever was there before.
    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(name, _)| (*name, std::env::var(name).ok()))
            .collect();
        // SAFETY: ENV_LOCK guarantees no other test or code path reads or
        // writes these variables while it is held.
        unsafe {
            for (name, value) in vars {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        f();
        // SAFETY: as above.
        unsafe {
            for (name, value) in saved {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn without_wlsctx_env(f: impl FnOnce()) {
        with_env(
            &[
                ("WLSCTX_APP_ID", None),
                ("WLSCTX_INSTANCE_ID", None),
                ("WLSCTX_SANDBOX_ENGINE", None),
                ("WLSCTX_SOCKET_PATH", None),
                ("WLSCTX_ALLOW_GLOBALS", None),
                ("WLSCTX_CLIPBOARD_POLICY", None),
            ],
            f,
        );
    }

    #[test]
    fn parses_explicit_arguments() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--app-id",
                "rustrover",
                "--instance-id",
                "work",
                "--sandbox-engine",
                "podman",
            ])
            .expect("explicit arguments must parse");
            assert_eq!(
                cli.listen.as_deref(),
                Some(std::path::Path::new("/run/pod/wayland-1"))
            );
            assert_eq!(cli.app_id, "rustrover");
            assert_eq!(cli.instance_id, "work");
            assert_eq!(cli.sandbox_engine, "podman");
            assert!(!cli.proxy);
            assert!(cli.tagged_socket.is_none());
            assert!(validate(&cli).is_ok());
        });
    }

    #[test]
    fn requires_listen_without_socket_activation() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--listen is required unless --socket-activation is set");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn requires_app_id_and_instance_id() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("app_id/instance_id are always required (no fd-name fallback)");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
            assert!(err.to_string().contains("--app-id"));
            assert!(err.to_string().contains("--instance-id"));
        });
    }

    #[test]
    fn socket_activation_conflicts_with_listen() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--listen",
                "/run/pod/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--socket-activation and --listen must conflict");
            assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
        });
    }

    #[test]
    fn socket_activation_parsing_needs_no_listen() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect("socket activation mode needs no --listen");
            assert!(cli.socket_activation);
            assert!(cli.listen.is_none());
            assert!(validate(&cli).is_ok());
        });
    }

    #[test]
    fn socket_activation_still_requires_explicit_ids() {
        without_wlsctx_env(|| {
            // The IDs must come from --app-id/--instance-id or their
            // environment variables; nothing is derived from LISTEN_FDNAMES.
            let err = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("socket-activation mode still requires explicit IDs");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn environment_variables_fill_required_arguments() {
        with_env(
            &[
                ("WLSCTX_APP_ID", Some("envapp")),
                ("WLSCTX_INSTANCE_ID", Some("envinst")),
                ("WLSCTX_SANDBOX_ENGINE", Some("envengine")),
                ("WLSCTX_SOCKET_PATH", Some("/run/pod/wayland-1")),
            ],
            || {
                let cli = Cli::try_parse_from(["wlsctx"]).expect("env vars satisfy all args");
                assert_eq!(cli.app_id, "envapp");
                assert_eq!(cli.instance_id, "envinst");
                assert_eq!(cli.sandbox_engine, "envengine");
                assert_eq!(
                    cli.listen.as_deref(),
                    Some(std::path::Path::new("/run/pod/wayland-1"))
                );
                assert!(validate(&cli).is_ok());
            },
        );
    }

    #[test]
    fn proxy_requires_tagged_socket() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from([
                "wlsctx",
                "--proxy",
                "--listen",
                "/run/pod/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--proxy requires --tagged-socket");
            assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn proxy_parses_with_tagged_socket() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--proxy",
                "--listen",
                "/run/pod/wayland-1",
                "--tagged-socket",
                "/run/user/1000/wlsctx-tagged",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect("proxy mode with a tagged socket must parse");
            assert!(cli.proxy);
            assert_eq!(
                cli.tagged_socket.as_deref(),
                Some(std::path::Path::new("/run/user/1000/wlsctx-tagged"))
            );
            assert!(validate(&cli).is_ok());
        });
    }

    #[test]
    fn clipboard_policy_defaults_to_allow_and_accepts_deny() {
        without_wlsctx_env(|| {
            let base = [
                "wlsctx",
                "--proxy",
                "--listen",
                "/run/pod/wayland-1",
                "--tagged-socket",
                "/tmp/t",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ];
            // Default.
            let cli = Cli::try_parse_from(base.iter().copied()).unwrap();
            assert_eq!(cli.clipboard_policy, "allow");
            assert!(validate(&cli).is_ok());
            // Explicit deny in proxy mode is fine.
            let cli = Cli::try_parse_from(
                std::iter::once("wlsctx")
                    .chain(base.iter().skip(1).copied())
                    .chain(["--clipboard-policy", "deny"]),
            )
            .unwrap();
            assert_eq!(cli.clipboard_policy, "deny");
            assert!(validate(&cli).is_ok());
        });
    }

    #[test]
    fn clipboard_policy_deny_requires_proxy() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--clipboard-policy",
                "deny",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .unwrap();
            let err = validate(&cli)
                .expect_err("--clipboard-policy deny without --proxy must be rejected");
            assert!(err.to_string().contains("--proxy"), "{err}");
        });
    }

    #[test]
    fn invalid_clipboard_policy_is_rejected() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--proxy",
                "--listen",
                "/run/pod/wayland-1",
                "--tagged-socket",
                "/tmp/t",
                "--clipboard-policy",
                "sometimes",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .unwrap();
            let err = validate(&cli).expect_err("an unknown policy value must be rejected");
            assert!(err.to_string().contains("sometimes"), "{err}");
        });
    }

    #[test]
    fn tagged_socket_without_proxy_is_rejected() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--tagged-socket",
                "/somewhere",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect("clap cannot express 'only with --proxy'; validate() catches it");
            let err = validate(&cli).expect_err("--tagged-socket without --proxy must be rejected");
            assert!(err.to_string().contains("--proxy"), "{err}");
        });
    }
}
