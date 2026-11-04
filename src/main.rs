//! wlsctx — run a command in an in-process namespaced sandbox
//! (`run`), tag a Wayland socket with an attached security context
//! (`wayland`, the original single-purpose mode) and optionally relay
//! sandboxed clients through a transparent proxy (`wayland --proxy`),
//! run the clipboard prompt broker (`broker`), or list/resolve the
//! broker's pending prompts (`decide`).
//!
//! The rework (PLAN.md) makes this a subcommand-based CLI: the
//! in-process sandbox (namespaces, private rootfs, landlock+seccomp
//! via `nono`) is created by this binary itself, no containers. The
//! transparent proxy and the prompt broker live in the library
//! (`src/lib.rs`) and are driven by the subcommands below.

mod cli;
mod profile;
mod sandbox;
mod systemd;
mod testutil;
mod wayland;

use anyhow::{Context, Result};
use clap::Parser;
use env_logger::Env;
use log::{Level, info, log_enabled};
use std::io::Write as _;
use std::path;
use std::time::Duration;

use crate::cli::{BrokerArgs, Cli, Command, DbusProxyArgs, DecideArgs, WaylandArgs, XwaylandArgs};
use crate::wayland::context::create_security_context;
use crate::wayland::listener::obtain_listener;
use wlsctx::proxy::LoopEnd;

fn main() -> Result<()> {
    let env = Env::default().default_filter_or("warn");
    env_logger::init_from_env(env);
    let cli = Cli::parse();
    cli.validate()?;

    // Restore the process name. Every self re-exec in the stack
    // (the MCS narrowing, the SIGHUP rebuild) execs `/proc/self/exe`,
    // and the kernel sets the comm to the executed path's basename —
    // "exe" — which would break name-based observation of re-exec'd
    // processes (ps, the journal, the audit log's comm field). The
    // write runs on every main() pass, so a re-exec'd instance
    // fixes its own name on the second pass; A and B inherit the
    // name at fork, and B's later app exec takes the app's. A
    // failed write only costs the cosmetic name (unconfined mode:
    // the name is already "wlsctx" from the binary, the write is a
    // no-op).
    // The bare name (no newline): this kernel's comm writer no longer
    // strips a trailing one (7.2.11 `comm_write` copies into a
    // zero-padded buffer and passes it to `set_task_comm` as-is), so
    // a newline would land *inside* the 15-char comm.
    let comm = c"wlsctx";
    let fd = unsafe { libc::open(c"/proc/self/comm".as_ptr(), libc::O_WRONLY) };
    if fd >= 0 {
        unsafe {
            libc::write(fd, comm.as_ptr().cast(), comm.count_bytes());
            libc::close(fd);
        }
    }

    match cli.command {
        // `run`: exec the command inside the sandbox and exit with
        // its exit code.
        Command::Run(args) => {
            // The app profile (TOML file, then built-in, then the
            // ad-hoc default — a malformed file is a hard error).
            let profile = match profile::load(&args.app_id)? {
                Some(p) => p,
                None => profile::Profile::adhoc(),
            };
            // The final GPU decision: explicit flags win over the
            // profile.
            let gpu = if args.gpu {
                true
            } else if args.no_gpu {
                false
            } else {
                profile.gpu
            };
            // The tagged Wayland socket (Phase 5.1): enabled by any of
            // --wayland / --listen / --socket-activation.
            let wayland = if args.wayland || args.listen.is_some() || args.socket_activation {
                Some(sandbox::WaylandSpec {
                    listen: args.listen.map(|p| p.to_string_lossy().into_owned()),
                    socket_activation: args.socket_activation,
                    sandbox_engine: args.sandbox_engine,
                })
            } else {
                None
            };
            let config = sandbox::SandboxConfig {
                app_id: args.app_id.clone(),
                instance_id: args.instance_id.clone(),
                network: match args.network.as_str() {
                    "none" => sandbox::namespaces::NetworkMode::None,
                    _ => sandbox::namespaces::NetworkMode::Shared,
                },
                profile,
                gpu,
                wayland,
            };
            let code = sandbox::run_sandboxed(&args.command, &config)?;
            info!("Sandboxed command exited with {code}");
            std::process::exit(code);
        }
        Command::Wayland(args) => {
            if args.proxy {
                run_proxy(&args)?
            } else {
                run_tag_and_park(&args)?
            }
        }
        Command::Broker(args) => run_broker(&args)?,
        Command::Decide(args) => run_decide(&args)?,
        Command::DbusProxy(args) => run_dbus_proxy(&args)?,
        Command::Xwayland(args) => run_xwayland(&args)?,
    }

    Ok(())
}

/// READY without unsetting NOTIFY_SOCKET: the `wayland` modes may
/// re-exec in place on SIGHUP, and the new process must be able to
/// re-notify.
fn sd_notify_ready() {
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
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

/// The proxy's global-allowlist policy, as given on the CLI.
///
/// An absent `--allow-globals` yields an empty list, which must be
/// the Phase 1 pass-through (every global shown). [`wlsctx::proxy::Policy::from_names`]
/// alone cannot express that distinction — it always builds an
/// *active* (filtering) policy, so fed with an empty list it hides
/// **everything** (the client cannot even bind `wl_compositor`).
/// Only a non-empty list engages the allowlist; blank entries
/// (e.g. `--allow-globals "a,,b"`) are ignored, mirroring
/// [`wlsctx::proxy::Policy::from_csv`].
fn policy_from_cli(names: Vec<String>) -> wlsctx::proxy::Policy {
    if names.is_empty() {
        wlsctx::proxy::Policy::all()
    } else {
        wlsctx::proxy::Policy::from_names(
            names
                .into_iter()
                .map(|n| n.trim().to_owned())
                .filter(|n| !n.is_empty()),
        )
    }
}

/// Tag-and-park: tag the listen socket with the security context,
/// hold the reference pipe, park until killed. Apps connect to the
/// tagged socket directly.
fn run_tag_and_park(args: &WaylandArgs) -> Result<()> {
    // Phase 8.2 (MCS): narrow our range to the instance's category
    // before binding the socket, so the tagged socket carries the
    // category and the post-re-exec pass (loop guard: range already
    // narrowed) rebinds it instead of racing a live one. No-op in
    // unconfined mode.
    wlsctx::mcs::self_reexec_with_category(&args.app_id, &args.instance_id)?;
    let (app_id, instance_id, listener) = obtain_listener(args)?;

    if log_enabled!(Level::Info)
        && let Ok(local_addr) = listener.local_addr()
    {
        info!("Listening on {local_addr:?} (tagged)")
    }

    // Keep BOTH the reference pipe (close_fd) and our copy of the
    // tagged listener open until process exit: the compositor holds
    // its own copies, so nothing is double-closed, but releasing
    // either here would make the socket's lifecycle diverge from
    // ours. See the ownership note on create_security_context.
    let close_fd = create_security_context(&listener, &args.sandbox_engine, &app_id, &instance_id)?;
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    sd_notify_ready();

    // SIGHUP rebuilds the tag in place (the only meaningful rebuild
    // here — the protocol tables re-load): a --listen run re-execs;
    // a socket-activated run exits cleanly for a systemd restart.
    // (Contrast `run`, where SIGHUP terminates the app and exits 129
    // — decision #33: there is no in-place rebuild of a live
    // sandbox.)
    match wlsctx::proxy::run_signal_loop()? {
        LoopEnd::Stopped => {}
        LoopEnd::ReExec => {
            // Closing the reference pipe invalidates the old tag;
            // dropping the listener frees the socket path / closes
            // the activated fd. (The setup connection was already
            // consumed by the tagging exchange.)
            drop(close_fd);
            drop(listener);
            if args.socket_activation {
                info!(
                    "SIGHUP: socket-activated; exiting for a systemd restart \
                     (a fresh socket is re-passed and re-tagged)"
                );
            } else {
                wlsctx::proxy::re_exec().with_context(|| "SIGHUP re-exec failed")?;
            }
        }
    }
    info!("Shutting down.");
    Ok(())
}

/// Proxy mode: tag a *second*, private listener; every app
/// connection to the public socket is relayed to the compositor
/// through a fresh security-context connection to it.
fn run_proxy(args: &WaylandArgs) -> Result<()> {
    // Phase 8.2 (MCS): narrow our range to the instance's category
    // before binding the public/tagged listeners, so both sockets
    // carry the category (and the post-re-exec pass rebinds them
    // cleanly — see `run_tag_and_park`). No-op in unconfined mode.
    wlsctx::mcs::self_reexec_with_category(&args.app_id, &args.instance_id)?;
    let (app_id, instance_id, public) = obtain_listener(args)?;
    // validate() guarantees Some in proxy mode.
    let tagged_path = resolve_listener_path(args.tagged_socket.as_deref().unwrap())?;
    let tagged = wlsctx::proxy::bind_listener(&tagged_path)
        .with_context(|| format!("binding the tagged listener {tagged_path:?}"))?;

    if log_enabled!(Level::Info)
        && let Ok(local_addr) = public.local_addr()
    {
        info!("Listening on {local_addr:?} (public); tagged listener at {tagged_path:?}")
    }

    let close_fd = create_security_context(&tagged, &args.sandbox_engine, &app_id, &instance_id)?;
    // The compositor now holds its own copy of the tagged listener
    // and accepts (and stamps) connections on it; the proxy only
    // connects to it by path. Dropping our copy guarantees we can
    // never accept on it (which would race the compositor and bypass
    // the context).
    drop(tagged);
    info!("Holding close_fd open to keep the tagged Wayland socket available {close_fd:?}");
    sd_notify_ready();

    let policy = policy_from_cli(args.allow_globals.clone());
    if policy.is_active() {
        info!(
            "Global allowlist active: showing {} interface(s) to sandboxed clients",
            policy.allow_count()
        );
    } else {
        info!("No global allowlist: pass-through (all globals shown)");
    }
    let clipboard = wlsctx::proxy::ClipboardPolicy::parse(&args.clipboard_policy)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if clipboard.is_active() {
        info!(
            "Clipboard gate active (deny): sandboxed reads of foreign selections come back empty"
        );
    } else {
        info!("Clipboard gate: pass-through (allow)");
    }
    // The audit identity: every selection event the relay observes is
    // recorded under the `audit` log target. Always on;
    // `RUST_LOG=warn` suppresses the stream.
    let audit = wlsctx::proxy::AuditConfig::new(app_id.clone(), instance_id.clone());
    // The optional prompt broker: when a denied read lands, the
    // relay asks here (a fresh connection per ask) before dropping.
    let broker = match &args.broker_socket {
        Some(p) => {
            let p = resolve_listener_path(p)?;
            if args.notify_copy_out {
                info!(
                    "Copy-out notifier: {} (each app write to the clipboard or primary \
                     selection fires a desktop notification; fire-and-forget, fails open)",
                    p.display()
                );
            } else {
                info!(
                    "Prompt broker: {} (denied reads are asked before dropping; a missing or \
                     slow broker fails closed)",
                    p.display()
                );
            }
            Some(wlsctx::proxy::BrokerConfig {
                socket: p,
                app: app_id.clone(),
                instance: instance_id.clone(),
                notify_copy_out: args.notify_copy_out,
                ..Default::default()
            })
        }
        None => None,
    };
    match wlsctx::proxy::event_loop(
        &public,
        &tagged_path,
        &policy,
        clipboard,
        audit,
        broker,
        None,
    )? {
        LoopEnd::Stopped => {}
        LoopEnd::ReExec => {
            // SIGHUP: close the reference pipe (invalidating the old
            // tag) and the public listener (freeing its path, or the
            // activated fd). In-flight app connections are severed
            // (the relay is per-connection).
            drop(close_fd);
            drop(public);
            if args.socket_activation {
                info!(
                    "SIGHUP: socket-activated; exiting for a systemd restart \
                     (a fresh socket is re-passed and the tag re-created)"
                );
            } else {
                wlsctx::proxy::re_exec().with_context(|| "SIGHUP re-exec failed")?;
            }
        }
    }
    info!("Shutting down.");
    Ok(())
}

/// Broker mode: sit on the broker socket (systemd-activated or bound
/// here), prompt the user for each denied foreign clipboard read, and
/// answer the proxy.
fn run_broker(args: &BrokerArgs) -> Result<()> {
    // MCS (phase 8.2): a confined broker narrows its range to
    // single-level `s0` before it binds or creates anything, so the
    // session-level objects it creates (the runtime dir, the
    // decision socket) stay reachable from every per-instance
    // category. This must run *before* `take_activated_socket`
    // (which consumes the LISTEN_* environment): the re-exec then
    // re-runs with the variables intact, the systemd-passed fd
    // (CLOEXEC-cleared by the manager) survives the execve, and the
    // post-re-exec invocation hits the loop guard (already `s0`).
    // No-op in unconfined mode.
    wlsctx::mcs::self_reexec_to_s0()?;
    let xdg = std::env::var("XDG_RUNTIME_DIR").context(
        "XDG_RUNTIME_DIR must be set: the broker keeps its decision \
         socket in $XDG_RUNTIME_DIR/wlsctx",
    )?;
    let listener = if args.socket_activation {
        wlsctx::broker::take_activated_socket().with_context(|| {
            "no socket was received via systemd socket activation (LISTEN_FDS is not set \
             or empty); run wlsctx through the wlsctx-broker.socket unit or use --listen"
        })?
    } else {
        let socket_path = args.listen.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "--listen is required when --socket-activation is not set \
                 (or set WLSCTX_SOCKET_PATH)"
            )
        })?;
        let socket_abspath = resolve_listener_path(socket_path)?;
        wlsctx::broker::bind_listener(&socket_abspath)
            .with_context(|| format!("binding {socket_abspath:?} failed"))?
    };
    sd_notify_ready();
    let broker_args = wlsctx::broker::BrokerArgs {
        runtime_dir: path::PathBuf::from(xdg).join("wlsctx"),
        auto_decide: args.auto_decide.as_deref().and_then(|s| {
            // validate() already rejected a bad value.
            wlsctx::broker::parse_decision(s).ok().map(|d| match d {
                wlsctx::broker::UserDecision::Allow => wlsctx::broker::AutoDecide::Allow,
                wlsctx::broker::UserDecision::Deny => wlsctx::broker::AutoDecide::Deny,
            })
        }),
        timeout: Duration::from_millis(args.broker_timeout_millis),
    };
    wlsctx::broker::run(&broker_args, listener).context("the broker event loop ended")?;
    info!("Shutting down.");
    Ok(())
}

/// Decide mode: talk to the broker's session decision socket.
/// Without `--decision`: list the pending prompts (oldest first).
/// With it: resolve the oldest pending prompt, or the one `--prompt`
/// names.
fn run_decide(args: &DecideArgs) -> Result<()> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").context(
        "XDG_RUNTIME_DIR must be set: the broker's decision socket \
         lives in $XDG_RUNTIME_DIR/wlsctx",
    )?;
    let socket = path::PathBuf::from(xdg)
        .join("wlsctx")
        .join(wlsctx::broker::DECISION_SOCKET);

    let listing = args.decision.is_none();
    let request = if listing {
        wlsctx::broker::encode_list_request()?
    } else {
        let d = wlsctx::broker::parse_decision(
            args.decision.as_deref().expect("checked by validate()"),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        wlsctx::broker::encode_decide_request(&d, args.prompt)?
    };
    info!(
        "decide: {} on the decision socket {socket:?}",
        if listing {
            "listing pending prompts"
        } else {
            "deciding"
        }
    );

    let mut stream = std::os::unix::net::UnixStream::connect(&socket).with_context(|| {
        format!(
            "connecting to the broker decision socket {socket:?} failed (is the broker \
             running — an --auto-decide broker never binds one?)"
        )
    })?;
    let _ = stream.set_read_timeout(Some(wlsctx::broker::DECIDER_READ_TIMEOUT));
    stream
        .write_all(request.as_bytes())
        .context("writing to the broker decision socket failed")?;

    let mut line = String::new();
    wlsctx::broker::read_line(&mut stream, &mut line)
        .context("reading the broker's reply on the decision socket failed")?;
    if line.is_empty() {
        anyhow::bail!("the broker decision socket closed without a reply");
    }

    // The reply is one of three known kinds; each decoder validates
    // the version and its own kind, so trying them in order
    // dispatches.
    match (
        wlsctx::broker::decode_pending_list(&line),
        wlsctx::broker::decode_resolution(&line),
        wlsctx::broker::decode_error_reply(&line),
    ) {
        (Ok(list), _, _) => {
            if list.prompts.is_empty() {
                println!("no pending broker prompts");
            } else {
                for p in &list.prompts {
                    println!(
                        "#{:<4} {}/{}  {:<8}  {:<24} ({} left)",
                        p.id,
                        p.app,
                        p.instance,
                        p.selection,
                        p.mime,
                        format_secs(p.expires_in_ms)
                    );
                }
            }
            Ok(())
        }
        (_, Ok(resolved), _) => {
            info!(
                "decide: prompt #{} resolved ({})",
                resolved.prompt, resolved.decision
            );
            println!("prompt #{}: {}", resolved.prompt, resolved.decision);
            Ok(())
        }
        (_, _, Ok(err)) => {
            let msg = match err.reason.as_str() {
                wlsctx::broker::REASON_NO_PENDING => {
                    "no pending broker prompt (it may have timed out already)"
                }
                wlsctx::broker::REASON_UNKNOWN_PROMPT => {
                    "unknown prompt (already resolved or expired)"
                }
                other => other,
            };
            let msg = match err.prompt {
                Some(id) => format!("prompt #{id}: {msg}"),
                None => msg.to_string(),
            };
            Err(anyhow::anyhow!("{msg}"))
        }
        _ => Err(anyhow::anyhow!(
            "malformed reply from the broker decision socket: {line:?}"
        )),
    }
}

/// The D-Bus session-bus sidecar: wrap `xdg-dbus-proxy` so the
/// sandboxed app's session-bus address reaches the real bus through a
/// filterable bridge.
fn run_dbus_proxy(args: &DbusProxyArgs) -> Result<()> {
    let mut config = wlsctx::dbus_proxy::Config {
        app_id: args.app_id.clone(),
        instance_id: args.instance_id.clone(),
        bus_address: args.bus_address.clone().unwrap_or_default(),
        socket_name: args
            .socket_name
            .clone()
            .unwrap_or_else(|| "bus.sock".into()),
        proxy_bin: args
            .proxy_bin
            .clone()
            .unwrap_or_else(|| "xdg-dbus-proxy".into()),
        ..Default::default()
    };
    for n in &args.see {
        config.rules.push(wlsctx::dbus_proxy::Rule {
            kind: "see",
            body: n.clone(),
        });
    }
    for n in &args.talk {
        config.rules.push(wlsctx::dbus_proxy::Rule {
            kind: "talk",
            body: n.clone(),
        });
    }
    for n in &args.own {
        config.rules.push(wlsctx::dbus_proxy::Rule {
            kind: "own",
            body: n.clone(),
        });
    }
    for n in &args.call {
        config.rules.push(wlsctx::dbus_proxy::Rule {
            kind: "call",
            body: n.clone(),
        });
    }
    for n in &args.broadcast {
        config.rules.push(wlsctx::dbus_proxy::Rule {
            kind: "broadcast",
            body: n.clone(),
        });
    }
    wlsctx::dbus_proxy::run(config)
}

/// The Xwayland satellite: wrap `Xwayland` so the sandboxed app gets
/// a per-instance X display (the sidecar hands Xwayland a bound X
/// socket in the instance runtime dir via `-listenfd` and gates on
/// its `-displayfd` display number).
fn run_xwayland(args: &XwaylandArgs) -> Result<()> {
    let config = wlsctx::xwayland::Config {
        app_id: args.app_id.clone(),
        instance_id: args.instance_id.clone(),
        display: args.display,
        socket_name: args
            .socket_name
            .clone()
            .unwrap_or_else(|| "xwayland.sock".into()),
        auth_name: args
            .auth_name
            .clone()
            .unwrap_or_else(|| "xwayland-auth".into()),
        wayland_display: args.wayland_display.clone().unwrap_or_default(),
        xwayland_bin: args
            .xwayland_bin
            .clone()
            .unwrap_or_else(|| "Xwayland".into()),
        rootless: args.rootless,
    };
    wlsctx::xwayland::run(config)
}

/// A millisecond count as a short human duration (for the listing).
fn format_secs(ms: u64) -> String {
    if ms.is_multiple_of(1000) {
        format!("{} s", ms / 1000)
    } else {
        format!("{:.1} s", ms as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::policy_from_cli;
    use crate::sandbox::userns::tests::run_in_child;
    use crate::testutil::TmpDir;
    use nix::sys::wait::waitpid;
    use nix::unistd::{ForkResult, fork};
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use wlsctx::pdeathsig::{ensure_shim, get, set};

    #[test]
    fn absent_flag_is_pass_through_not_hide_all() {
        // Regression (found by the live-desktop e2e): an empty list is
        // "no flag", and must show every global, not hide all of them.
        let p = policy_from_cli(Vec::new());
        assert!(!p.is_active());
        assert_eq!(p.allow_count(), 0);
        assert!(p.allows("wl_compositor"));
        assert!(p.allows("wp_security_context_manager_v1"));
        assert!(p.allows("anything"));
    }

    #[test]
    fn non_empty_flag_engages_the_allowlist() {
        let p = policy_from_cli(vec!["wl_shm".into(), "wl_compositor".into()]);
        assert!(p.is_active());
        assert_eq!(p.allow_count(), 2);
        assert!(p.allows("wl_shm"));
        assert!(p.allows("wl_compositor"));
        assert!(!p.allows("wl_seat"));
    }

    #[test]
    fn blank_entries_are_ignored() {
        // `--allow-globals " wl_shm ,, wl_seat "`: blanks drop out, the
        // surrounding whitespace is trimmed.
        let p = policy_from_cli(vec![" wl_shm ".into(), "".into(), " wl_seat ".into()]);
        assert!(p.is_active());
        assert_eq!(p.allow_count(), 2);
        assert!(p.allows("wl_shm"));
        assert!(p.allows("wl_seat"));
    }

    /// Compile a C probe that reads its own `PR_GET_PDEATHSIG` and
    /// exits 0 iff it is 10 (`SIGUSR1`), 3 if the syscall fails, 4 if
    /// it is anything else. The read uses the 7.x convention (the
    /// value is written to the pointer in `arg2`), so the probe is a
    /// faithful stand-in for what the app process sees after its exec.
    fn build_probe(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let c = dir.join(format!("{name}.c"));
        std::fs::write(
            &c,
            r#"#include <sys/prctl.h>
#include <unistd.h>
int main(void) {
    int v = -12345;
    if (prctl(PR_GET_PDEATHSIG, &v, 0, 0, 0) != 0) {
        return 3;
    }
    return (v == 10) ? 0 : 4;
}
"#,
        )
        .unwrap_or_else(|e| panic!("writing the probe source {c:?}: {e}"));
        let bin = dir.join(name);
        let out = std::process::Command::new("cc")
            .arg("-O2")
            .arg("-o")
            .arg(&bin)
            .arg(&c)
            .output()
            .unwrap_or_else(|e| panic!("invoking cc for {name}: {e}"));
        if !out.status.success() {
            panic!(
                "cc {name} failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        bin
    }

    /// decision #42: the 7.x set/fork-reset mechanics. `set` must
    /// read back its value; `fork` must **reset** the child to 0
    /// (not inherit it); and the child's own `set` must then read
    /// back. This is why every link in the cascade arms itself after
    /// its own fork instead of relying on inheritance.
    #[test]
    fn pdeathsig_set_get_and_fork_reset() {
        let (code, out, err) = run_in_child(|o| {
            if !set(10) {
                let _ = writeln!(o, "set: failed");
                return 11;
            }
            let after_set = get();
            let _ = writeln!(o, "after_set: {after_set}");
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    // The fork just now reset the value to 0.
                    let in_child = get();
                    let _ = writeln!(o, "in_child: {in_child}");
                    if !set(10) {
                        let _ = writeln!(o, "child set: failed");
                        std::process::exit(12);
                    }
                    let after_set2 = get();
                    let _ = writeln!(o, "after_set2: {after_set2}");
                    std::process::exit(0);
                }
                Ok(ForkResult::Parent { child }) => {
                    // Wait for the grandchild so its (shared) pipe
                    // write end is released before the drain.
                    let _ = waitpid(Some(child), None);
                    0
                }
                Err(e) => {
                    let _ = writeln!(o, "fork: {e}");
                    13
                }
            }
        });
        assert_eq!(code, Some(0), "unexpected exit:\n{out}\n{err}");
        assert!(
            out.contains("after_set: 10"),
            "set must read back 10:\n{out}"
        );
        assert!(out.contains("in_child: 0"), "fork must reset to 0:\n{out}");
        assert!(
            out.contains("after_set2: 10"),
            "the child's set must read back 10:\n{out}"
        );
    }

    /// decision #42: a plain same-uid `exec` (no setuid/setgid, no
    /// capability change) does **not** clear the belt — `fs/exec.c`
    /// clears `pdeathsig` only for `bprm->secureexec` and
    /// `kernel/cred.c` only on an actual credential change. So the
    /// pre-exec `set` survives the exec. (The confined run clears it
    /// — a SELinux credential change — which is what the shim
    /// re-arms; see the next test.)
    #[test]
    fn plain_exec_preserves_the_pdeathsig_belt() {
        let dir = TmpDir::new("pdeathsig-exec");
        let probe = build_probe(dir.path(), "exec-probe");
        let probe_s = probe.to_string_lossy().into_owned();
        let (code, out, err) = run_in_child(move |o| {
            if !set(10) {
                let _ = writeln!(o, "set: failed");
                std::process::exit(14);
            }
            // A plain exec: the belt (10) must survive. `exec` (safe
            // in this toolchain) replaces the process on success —
            // the only way out of the call is its failure `Error`.
            let mut cmd = std::process::Command::new(&probe_s);
            let e = cmd.exec();
            let _ = writeln!(o, "exec: {e}");
            std::process::exit(15);
        });
        assert_eq!(
            code,
            Some(0),
            "the probe must read back 10 after a plain exec:\n{out}\n{err}"
        );
    }

    /// decision #42: with **no** pre-exec belt, the `LD_PRELOAD`
    /// shim's constructor re-arms the signal across the exec. This is
    /// the confined-mode answer (the exec's SELinux credential change
    /// clears the belt) and the belt-and-bridle for any exec that
    /// does clear it.
    #[test]
    fn pdeathsig_shim_rearms_after_exec() {
        let dir = TmpDir::new("pdeathsig-shim");
        let shim = ensure_shim(dir.path().to_str().expect("an absolute path"), 10)
            .expect("the shim must compile (cc is on the dev host)");
        let probe = build_probe(dir.path(), "shim-probe");
        let probe_s = probe.to_string_lossy().into_owned();
        let shim_s = shim.to_string_lossy().into_owned();
        let (code, out, err) = run_in_child(move |o| {
            // No belt: leave the value at 0 (what the fork reset it
            // to) so the *only* thing that can arm it is the shim.
            let _ = set(0);
            let mut cmd = std::process::Command::new(&probe_s);
            cmd.env("LD_PRELOAD", &shim_s);
            // As above: the only way out of `exec` is a failure `Error`.
            let e = cmd.exec();
            let _ = writeln!(o, "exec: {e}");
            std::process::exit(17);
        });
        assert_eq!(
            code,
            Some(0),
            "the shim must re-arm 10 across the exec:\n{out}\n{err}"
        );
    }
}
