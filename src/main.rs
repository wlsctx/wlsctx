//! The wlsctx binary: tag-and-park (the default), transparent Wayland
//! proxy (`--proxy`), the clipboard prompt broker (`--broker`), or
//! sending a decision to a pending broker prompt (`--decide`).

use std::io::Write as _;
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
    /// Application ID in security context (required except in
    /// --broker/--decide mode)
    #[arg(long, env = "WLSCTX_APP_ID")]
    app_id: Option<String>,
    /// Instance ID in security context (required except in
    /// --broker/--decide mode)
    #[arg(long, env = "WLSCTX_INSTANCE_ID")]
    instance_id: Option<String>,
    /// Sandbox engine ID in security context (required except in
    /// --broker/--decide mode)
    #[arg(long, env = "WLSCTX_SANDBOX_ENGINE")]
    sandbox_engine: Option<String>,
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
    /// (Proxy mode only) path of the prompt broker's socket: when the
    /// clipboard gate drops a foreign read, the proxy asks the broker
    /// (which prompts the user on the host); an approved read opens
    /// the gate's intent window (1500 ms) and goes through. When the
    /// broker is missing or times out, the read is dropped anyway
    #[arg(long, env = "WLSCTX_BROKER_SOCKET")]
    broker_socket: Option<path::PathBuf>,
    /// Run as the clipboard prompt broker (a host user service,
    /// outside the sandbox): each denied foreign clipboard read
    /// arrives as a JSON request on the listen socket, is announced
    /// with a desktop notification, and is allowed or denied by the
    /// user on a private decision socket (see src/broker.rs)
    #[arg(long, conflicts_with = "proxy", conflicts_with = "decide")]
    broker: bool,
    /// (Broker mode) decide every request automatically without
    /// prompting — a test hook
    #[arg(long, requires = "broker", value_name = "DECISION")]
    auto_decide: Option<String>,
    /// (Broker mode) how long to wait for the user's decision, in
    /// milliseconds (a timeout is a deny)
    #[arg(long, env = "WLSCTX_BROKER_TIMEOUT_MILLIS", requires = "broker", default_value_t = 30_000, value_name = "MS")]
    broker_timeout_millis: u64,
    /// Send a decision to the pending broker prompt (the most recent
    /// one, via the `latest` pointer in the runtime directory) —
    /// normally invoked by a keybinding or a notification action
    #[arg(long, conflicts_with = "proxy", conflicts_with = "broker")]
    decide: bool,
    /// (Decide mode) the decision to send: allow or deny
    #[arg(long, requires = "decide", value_name = "DECISION")]
    decision: Option<String>,
}

/// Validate the argument combinations clap cannot express
/// (`--tagged-socket` and `--allow-globals` are meaningless outside
/// `--proxy` mode; the security-context IDs are required outside
/// broker/decide mode).
fn validate(cli: &Cli) -> Result<()> {
    if cli.broker || cli.decide {
        // The broker learns app/instance per request from the proxy;
        // the decider is a one-shot CLI. The security-context IDs
        // apply to neither.
    } else if let Some(missing) = [
        (cli.app_id.is_none(), "--app-id"),
        (cli.instance_id.is_none(), "--instance-id"),
        (cli.sandbox_engine.is_none(), "--sandbox-engine"),
    ]
    .iter()
    .find(|(is_missing, _)| *is_missing)
    {
        bail!(
            "{0} is required (or set the matching WLSCTX_* environment variable) \
             unless running --broker or --decide",
            missing.1
        );
    }
    if cli.broker && cli.auto_decide.is_some()
        && let Err(e) = wlsctx::broker::parse_decision(cli.auto_decide.as_deref().unwrap())
    {
        bail!("{e}");
    }
    if cli.decide
        && let Err(e) = wlsctx::broker::parse_decision(
            cli.decision
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--decide needs --decision (allow or deny)"))?,
        )
    {
        bail!("{e}");
    }
    if !cli.proxy
        && let Some(p) = &cli.broker_socket
    {
        bail!(
            "--broker-socket ({p:?}) is only valid together with --proxy; \
             the broker socket is only used to ask about dropped reads, \
             which only the relay can have"
        );
    }
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
    if cli.broker {
        run_broker(&cli)
    } else if cli.decide {
        run_decide(&cli)
    } else if cli.proxy {
        run_proxy(&cli)
    } else {
        run_tag_and_park(&cli)
    }
}

/// Broker mode: sit on the broker socket (systemd-activated or bound
/// here), prompt the user for each denied foreign clipboard read, and
/// answer the proxy.
fn run_broker(cli: &Cli) -> Result<()> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").context(
        "XDG_RUNTIME_DIR must be set: the broker keeps its decision \
         sockets and the `latest` pointer in $XDG_RUNTIME_DIR/wlsctx",
    )?;
    let listener = if cli.socket_activation {
        wlsctx::broker::take_activated_socket().with_context(|| {
            "no socket was received via systemd socket activation (LISTEN_FDS is not set \
             or empty); run wlsctx through the wlsctx-broker.socket unit or use --listen"
        })?
    } else {
        let socket_path = cli.listen.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--listen is required when --socket-activation is not set")
        })?;
        let socket_abspath = resolve_listener_path(socket_path)?;
        wlsctx::broker::bind_listener(&socket_abspath)
            .with_context(|| format!("binding {socket_abspath:?} failed"))?
    };
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
    let args = wlsctx::broker::BrokerArgs {
        runtime_dir: path::PathBuf::from(xdg).join("wlsctx"),
        auto_decide: cli.auto_decide.as_deref().map(|s| {
            wlsctx::broker::parse_decision(s)
                .ok()
                .map(|d| match d {
                    wlsctx::broker::UserDecision::Allow => wlsctx::broker::AutoDecide::Allow,
                    wlsctx::broker::UserDecision::Deny => wlsctx::broker::AutoDecide::Deny,
                })
                .unwrap_or_else(|| {
                    // validate() already rejected a bad value.
                    unreachable!()
                })
        }),
        timeout: std::time::Duration::from_millis(cli.broker_timeout_millis),
    };
    wlsctx::broker::run(&args, listener).context("the broker event loop ended")?;
    info!("Shutting down.");
    Ok(())
}

/// Decide mode: send the user's decision to the most recent pending
/// broker prompt (the one whose decision socket the `latest` pointer
/// names).
fn run_decide(cli: &Cli) -> Result<()> {
    let decision = wlsctx::broker::parse_decision(
        cli.decision
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--decide needs --decision (allow or deny)"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let xdg = std::env::var("XDG_RUNTIME_DIR").context(
        "XDG_RUNTIME_DIR must be set: the broker's `latest` pointer \
         lives in $XDG_RUNTIME_DIR/wlsctx",
    )?;
    let latest = path::PathBuf::from(xdg).join("wlsctx").join("latest");
    let target = std::fs::read_to_string(&latest)
        .with_context(|| {
            format!(
                "no pending broker prompt ({latest:?} is missing); is a sandboxed app \
                 waiting for consent right now?"
            )
        })?
        .trim()
        .to_string();
    let mut stream = std::os::unix::net::UnixStream::connect(&target)
        .with_context(|| format!("connecting to the broker decision socket {target:?} failed"))?;
    stream
        .write_all(wlsctx::broker::encode_user_decision(&decision)?.as_bytes())
        .context("writing the decision to the broker failed")?;
    info!("sent {decision:?} to the broker prompt at {target:?}");
    Ok(())
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
        cli.sandbox_engine.as_deref().context("--sandbox-engine is required")?,
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
        cli.sandbox_engine.as_deref().context("--sandbox-engine is required")?,
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
    // The optional prompt broker: when a denied read lands, the
    // relay asks here (a fresh connection per ask) before dropping.
    let broker = match &cli.broker_socket {
        Some(p) => {
            let p = resolve_listener_path(p)?;
            info!(
                "Prompt broker: {} (denied reads are asked before dropping; a missing or \
                 slow broker fails closed)",
                p.display()
            );
            Some(wlsctx::proxy::BrokerConfig {
                socket: p,
                app: app_id,
                instance: instance_id,
                ..Default::default()
            })
        }
        None => None,
    };
    wlsctx::proxy::event_loop(&public, &tagged_path, &policy, clipboard, broker, None)?;
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
    // validate() already required these in every mode this is used in
    // (tag-and-park and proxy).
    let app_id = cli
        .app_id
        .clone()
        .context("--app-id is required (or set WLSCTX_APP_ID)")?;
    let instance_id = cli
        .instance_id
        .clone()
        .context("--instance-id is required (or set WLSCTX_INSTANCE_ID)")?;
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
            assert_eq!(cli.app_id.as_deref(), Some("rustrover"));
            assert_eq!(cli.instance_id.as_deref(), Some("work"));
            assert_eq!(cli.sandbox_engine.as_deref(), Some("podman"));
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
            // The IDs are optional at parse time so that --broker and
            // --decide modes (which need no security-context IDs) can
            // parse; validate() rejects their absence in every other
            // mode. Nothing is derived from fd names.
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--listen",
                "/run/pod/wayland-1",
                "--sandbox-engine",
                "podman",
            ])
            .expect("IDs are optional at parse time");
            let err = validate(&cli).unwrap_err();
            assert!(err.to_string().contains("--app-id"), "{err}");
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
            // They parse as absent and are rejected by validate().
            let cli = Cli::try_parse_from([
                "wlsctx",
                "--socket-activation",
                "--sandbox-engine",
                "podman",
            ])
            .expect("IDs are optional at parse time");
            let err = validate(&cli).unwrap_err();
            assert!(err.to_string().contains("--app-id"), "{err}");
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
                assert_eq!(cli.app_id.as_deref(), Some("envapp"));
                assert_eq!(cli.instance_id.as_deref(), Some("envinst"));
                assert_eq!(cli.sandbox_engine.as_deref(), Some("envengine"));
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
