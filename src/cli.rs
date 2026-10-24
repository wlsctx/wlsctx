//! Command-line interface.
//!
//! A subcommand tree (PLAN.md §5): `run` is the sandboxed-execution
//! path (ad-hoc for now; profile-driven in later phases); `wayland`
//! is the original single-mode behaviour (a tagged Wayland socket),
//! optionally relayed through the transparent proxy (`--proxy`);
//! `broker` runs the clipboard prompt broker (a host user service);
//! and `decide` lists or resolves the broker's pending prompts.

use clap::builder::TypedValueParser;
use clap::{Args, Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::path;

use anyhow::{Result, bail};

/// wlsctx: run commands inside a namespaced, landlock+seccomp
/// confined sandbox; tag a Wayland socket with a security context so
/// the compositor can identify sandboxed clients (and optionally
/// relay clients through the transparent proxy); run the clipboard
/// prompt broker; or list/resolve the broker's pending prompts.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Run a command inside the wlsctx sandbox
    Run(RunArgs),
    /// Set up a Wayland socket with an attached security context
    /// (or, with --proxy, relay sandboxed clients through the
    /// transparent proxy)
    ///
    /// See https://wayland.app/protocols/security-context-v1
    Wayland(WaylandArgs),
    /// Run the clipboard prompt broker (a host user service, outside
    /// the sandbox)
    Broker(BrokerArgs),
    /// List the broker's pending prompts, or send a decision to one
    /// of them (the oldest, or the one --prompt names) on the
    /// broker's session decision socket
    Decide(DecideArgs),
}

impl Cli {
    /// Validate the argument combinations clap cannot express:
    /// the proxy-only `wayland` flags (clap can require
    /// `--tagged-socket` *when* `--proxy` is set, but not the
    /// inverse, and neither can test a `--clipboard-policy` value),
    /// and the `allow`/`deny` decision keywords of the broker and
    /// decide subcommands.
    pub(crate) fn validate(&self) -> Result<()> {
        match &self.command {
            Command::Wayland(w) => {
                if !w.proxy && w.tagged_socket.is_some() {
                    bail!(
                        "--tagged-socket ({:?}) is only valid together with --proxy; \
                         in tag-and-park mode the --listen socket itself is the tagged one",
                        w.tagged_socket,
                    );
                }
                if !w.proxy && !w.allow_globals.is_empty() {
                    bail!(
                        "--allow-globals is only valid together with --proxy; \
                         the tag-and-park mode has no relay to filter"
                    );
                }
                if !w.proxy && w.broker_socket.is_some() {
                    bail!(
                        "--broker-socket ({:?}) is only valid together with --proxy; \
                         the broker socket is only used to ask about dropped reads, \
                         which only the relay can have",
                        w.broker_socket,
                    );
                }
                if w.notify_copy_out {
                    if !w.proxy {
                        bail!(
                            "--notify-copy-out is only valid together with --proxy; \
                             only the relay sees the app's set_selection traffic"
                        );
                    }
                    if w.broker_socket.is_none() {
                        bail!(
                            "--notify-copy-out needs --broker-socket: the copy-out \
                             notification is delivered to the host broker over that socket"
                        );
                    }
                }
                let clipboard = wlsctx::proxy::ClipboardPolicy::parse(&w.clipboard_policy)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                if !w.proxy && clipboard != wlsctx::proxy::ClipboardPolicy::Allow {
                    bail!(
                        "--clipboard-policy {} is only valid together with --proxy; \
                         the tag-and-park mode has no relay to filter",
                        w.clipboard_policy,
                    );
                }
            }
            Command::Broker(b) => {
                if let Some(s) = &b.auto_decide {
                    wlsctx::broker::parse_decision(s).map_err(|e| anyhow::anyhow!("{e}"))?;
                }
            }
            Command::Decide(d) => {
                if let Some(s) = &d.decision {
                    wlsctx::broker::parse_decision(s).map_err(|e| anyhow::anyhow!("{e}"))?;
                }
            }
            Command::Run(_) => {}
        }
        Ok(())
    }
}

/// Arguments of `wlsctx run`.
#[derive(Args, Debug)]
pub(crate) struct RunArgs {
    /// Application ID: part of the instance hostname
    /// (`wlsctx-<app>-<instance>`) and of the per-instance cgroup
    /// name (only [A-Za-z0-9._-])
    #[arg(long, default_value = "app")]
    pub(crate) app_id: String,
    /// Instance ID: part of the hostname and cgroup name
    #[arg(long, default_value = "1")]
    pub(crate) instance_id: String,
    /// Network mode: `shared` (default — the host netns; nono filters
    /// it in a later phase) or `none` (a bare netns with only
    /// loopback, brought up)
    #[arg(
        long,
        value_parser = clap::builder::PossibleValuesParser::new(["shared", "none"]),
        default_value = "shared"
    )]
    pub(crate) network: String,
    /// Force GPU access (`/dev/dri` is built in the sandbox) even if
    /// the app profile disables it
    #[arg(long, overrides_with = "no_gpu")]
    pub(crate) gpu: bool,
    /// Skip the GPU even if the app profile enables it
    #[arg(long, overrides_with = "gpu")]
    pub(crate) no_gpu: bool,
    /// Create a tagged Wayland socket for the app (default name
    /// `wayland-1` in the per-instance runtime dir; the app's
    /// `WAYLAND_DISPLAY` points at it and it never sees the host's
    /// socket). Needs a running wlroots compositor providing
    /// `wp_security_context_manager_v1`
    #[arg(long)]
    pub(crate) wayland: bool,
    /// Path of the tagged Wayland socket: an absolute path as given,
    /// a relative path in the per-instance runtime dir. Implies
    /// `--wayland`
    #[arg(long, conflicts_with = "socket_activation")]
    pub(crate) listen: Option<path::PathBuf>,
    /// Adopt the tagged Wayland socket from systemd socket activation
    /// (LISTEN_FDS) instead of binding a path. Implies `--wayland`
    #[arg(long, conflicts_with = "listen")]
    pub(crate) socket_activation: bool,
    /// The value the tagged socket is tagged with
    /// (`wp_security_context_v1.set_sandbox_engine`)
    #[arg(long, default_value = "wlsctx")]
    pub(crate) sandbox_engine: String,
    /// Command and its arguments, run inside the sandbox
    /// (everything after `--`; e.g. `wlsctx run -- /bin/sh -c 'id'`)
    #[arg(trailing_var_arg = true, required = true)]
    pub(crate) command: Vec<OsString>,
}

/// Arguments of `wlsctx wayland` (the original single-mode CLI,
/// optionally the transparent proxy).
#[derive(Args, Debug)]
pub(crate) struct WaylandArgs {
    /// Application ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_APP_ID", value_parser = NonEmpty::new("app-id"))]
    pub(crate) app_id: String,
    /// Instance ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_INSTANCE_ID", value_parser = NonEmpty::new("instance-id"))]
    pub(crate) instance_id: String,
    /// Sandbox engine ID in security context (must not be empty)
    #[arg(
        long,
        env = "WLSCTX_SANDBOX_ENGINE",
        value_parser = NonEmpty::new("sandbox-engine")
    )]
    pub(crate) sandbox_engine: String,
    /// Listen on Unix socket (required unless --socket-activation is
    /// set). In proxy mode this is the *public* socket the apps
    /// connect to; in tag-and-park it is the tagged socket itself
    #[arg(
        long,
        env = "WLSCTX_SOCKET_PATH",
        required_unless_present = "socket_activation"
    )]
    pub(crate) listen: Option<path::PathBuf>,
    /// Receive socket via systemd socket activation (LISTEN_FDS)
    #[arg(long, conflicts_with = "listen")]
    pub(crate) socket_activation: bool,
    /// Run as a transparent Wayland proxy: every connection to the
    /// listen socket is relayed to the compositor through a
    /// security-context connection to --tagged-socket, so the
    /// compositor applies per-context policy to the sandboxed client
    #[arg(long)]
    pub(crate) proxy: bool,
    /// (Proxy mode only) path of the tagged listener: bound here,
    /// passed to the compositor, and the only socket the proxy
    /// connects to upstream. It must be unreachable from the
    /// sandboxed app (e.g. the sidecar's private runtime dir)
    #[arg(long, required_if_eq("proxy", "true"))]
    pub(crate) tagged_socket: Option<path::PathBuf>,
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
    pub(crate) allow_globals: Vec<String>,
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
    pub(crate) clipboard_policy: String,
    /// (Proxy mode only) path of the prompt broker's socket: when the
    /// clipboard gate drops a foreign read, the proxy asks the broker
    /// (which prompts the user on the host); an approved read opens
    /// the gate's intent window (1500 ms) and goes through. When the
    /// broker is missing or times out, the read is dropped anyway
    #[arg(long, env = "WLSCTX_BROKER_SOCKET")]
    pub(crate) broker_socket: Option<path::PathBuf>,
    /// (Proxy mode only) notify the host broker — a desktop
    /// notification — each time a sandboxed app writes to the clipboard
    /// or the primary selection (a `set_selection`). This is the
    /// copy-*out* signal: the data the app just placed is now reachable
    /// by every client on the desktop. Fire-and-forget and fail-open:
    /// a missing broker only loses the notice; the write is never
    /// blocked or altered. Requires `--broker-socket` (the notification
    /// travels over that socket); independent of `--clipboard-policy`
    /// (a write is always forwarded)
    #[arg(long, env = "WLSCTX_NOTIFY_COPY_OUT")]
    pub(crate) notify_copy_out: bool,
}

/// Arguments of `wlsctx broker`.
#[derive(Args, Debug)]
pub(crate) struct BrokerArgs {
    /// Listen on Unix socket (required unless --socket-activation is
    /// set; the proxy's --broker-socket points here)
    #[arg(long, env = "WLSCTX_SOCKET_PATH")]
    pub(crate) listen: Option<path::PathBuf>,
    /// Receive socket via systemd socket activation (LISTEN_FDS)
    #[arg(long, conflicts_with = "listen")]
    pub(crate) socket_activation: bool,
    /// Decide every request automatically without prompting — a test
    /// hook (an interactive broker never binds the decision socket)
    #[arg(long, value_name = "DECISION")]
    pub(crate) auto_decide: Option<String>,
    /// How long to wait for the user's decision, in milliseconds (a
    /// timeout is a deny)
    #[arg(
        long,
        env = "WLSCTX_BROKER_TIMEOUT_MILLIS",
        default_value_t = 30_000,
        value_name = "MS"
    )]
    pub(crate) broker_timeout_millis: u64,
}

/// Arguments of `wlsctx decide` (a one-shot client of the broker's
/// session decision socket).
#[derive(Args, Debug)]
pub(crate) struct DecideArgs {
    /// The decision to send: allow or deny. Without it, `decide`
    /// lists the pending prompts.
    #[arg(long, value_name = "DECISION")]
    pub(crate) decision: Option<String>,
    /// The id of the pending prompt to decide (from the listing).
    /// Omitted: the oldest pending prompt.
    #[arg(long, value_name = "ID")]
    pub(crate) prompt: Option<u32>,
}

/// A value parser that rejects the empty string for the security-context
/// IDs.
///
/// Clap treats an *empty* environment variable as present-with-a-value
/// (`WLSCTX_APP_ID=` in an environment.d file is a very common typo).
/// An empty ID would tag the socket with a context that matches no
/// compositor policy — the security labeling silently stops working
/// while the process looks healthy. Rejecting it at parse time fails
/// loudly instead.
#[derive(Clone, Copy, Debug)]
struct NonEmpty {
    field: &'static str,
}

impl NonEmpty {
    fn new(field: &'static str) -> Self {
        Self { field }
    }
}

impl TypedValueParser for NonEmpty {
    type Value = String;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_string_lossy();
        if value.is_empty() {
            let field = self.field;
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!(
                    "--{field} (or its WLSCTX_* environment variable) must not be empty: \
                     an empty ID would tag the socket with a context that matches no \
                     compositor policy, silently disabling the sandbox; set a non-empty value"
                ),
            ));
        }
        Ok(value.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{BrokerArgs, Cli, Command, DecideArgs, WaylandArgs};
    use crate::testutil::{with_env, without_wlsctx_env};
    use clap::Parser;
    use clap::error::ErrorKind;

    /// Parse in `wayland` subcommand form and extract the args.
    fn parse_wayland(argv: &[&str]) -> Result<WaylandArgs, clap::Error> {
        let cli = Cli::try_parse_from(argv)?;
        Ok(match cli.command {
            Command::Wayland(args) => args,
            _ => unreachable!("parse_wayland must only parse the wayland subcommand"),
        })
    }

    /// Parse in `broker` subcommand form and extract the args.
    fn parse_broker(argv: &[&str]) -> Result<BrokerArgs, clap::Error> {
        let cli = Cli::try_parse_from(argv)?;
        Ok(match cli.command {
            Command::Broker(args) => args,
            _ => unreachable!("parse_broker must only parse the broker subcommand"),
        })
    }

    /// Parse in `decide` subcommand form and extract the args.
    fn parse_decide(argv: &[&str]) -> Result<DecideArgs, clap::Error> {
        let cli = Cli::try_parse_from(argv)?;
        Ok(match cli.command {
            Command::Decide(args) => args,
            _ => unreachable!("parse_decide must only parse the decide subcommand"),
        })
    }

    #[test]
    fn parses_explicit_arguments() {
        without_wlsctx_env(|| {
            let args = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--app-id",
                "rustrover",
                "--instance-id",
                "work",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("explicit arguments must parse");
            assert_eq!(
                args.listen.as_deref(),
                Some(std::path::Path::new("/run/wlsctx/wayland-1"))
            );
            assert_eq!(args.app_id, "rustrover");
            assert_eq!(args.instance_id, "work");
            assert_eq!(args.sandbox_engine, "wlsctx");
            assert!(!args.socket_activation);
            assert!(!args.proxy);
            assert!(args.tagged_socket.is_none());
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--app-id",
                "rustrover",
                "--instance-id",
                "work",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("tag-and-park validates");
            cli.validate().expect("tag-and-park validates");
        });
    }

    #[test]
    fn requires_subcommand() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from(["wlsctx"]).expect_err("a subcommand is required");
            // Clap answers a missing (required) subcommand by showing
            // the help; the error kind reflects that.
            assert_eq!(
                err.kind(),
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            );
        });
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from(["wlsctx", "wlsctx"])
                .expect_err("unknown subcommands must be rejected");
            assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
        });
    }

    #[test]
    fn wayland_requires_listen_without_socket_activation() {
        without_wlsctx_env(|| {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect_err("--listen is required unless --socket-activation is set");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn wayland_requires_app_id_and_instance_id() {
        without_wlsctx_env(|| {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect_err("app_id/instance_id are always required (no fd-name fallback)");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
            let msg = err.to_string();
            assert!(msg.contains("--app-id"), "{msg}");
            assert!(msg.contains("--instance-id"), "{msg}");
        });
    }

    #[test]
    fn wayland_socket_activation_conflicts_with_listen() {
        without_wlsctx_env(|| {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--socket-activation",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect_err("--socket-activation and --listen must conflict");
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        });
    }

    #[test]
    fn wayland_socket_activation_parsing_needs_no_listen() {
        without_wlsctx_env(|| {
            let args = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--socket-activation",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("socket activation mode needs no --listen");
            assert!(args.socket_activation);
            assert!(args.listen.is_none());
        });
    }

    #[test]
    fn wayland_socket_activation_still_requires_explicit_ids() {
        without_wlsctx_env(|| {
            // The IDs must come from --app-id/--instance-id or their
            // environment variables; nothing is derived from LISTEN_FDNAMES.
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--socket-activation",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect_err("socket-activation mode still requires explicit IDs");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn wayland_environment_variables_fill_required_arguments() {
        with_env(
            &[
                ("WLSCTX_APP_ID", Some("envapp")),
                ("WLSCTX_INSTANCE_ID", Some("envinst")),
                ("WLSCTX_SANDBOX_ENGINE", Some("envengine")),
                ("WLSCTX_SOCKET_PATH", Some("/run/wlsctx/wayland-1")),
            ],
            || {
                let args =
                    parse_wayland(&["wlsctx", "wayland"]).expect("env vars satisfy all args");
                assert_eq!(args.app_id, "envapp");
                assert_eq!(args.instance_id, "envinst");
                assert_eq!(args.sandbox_engine, "envengine");
                assert_eq!(
                    args.listen.as_deref(),
                    Some(std::path::Path::new("/run/wlsctx/wayland-1"))
                );
            },
        );
    }

    #[test]
    fn wayland_explicit_arguments_take_precedence_over_env() {
        // The socket-activated deployment relied on exactly this: the
        // unit passes --listen on the command line while the IDs come
        // from the WLSCTX_* environment, and the two sources may
        // disagree.
        with_env(
            &[
                ("WLSCTX_APP_ID", Some("envapp")),
                ("WLSCTX_INSTANCE_ID", Some("envinst")),
                ("WLSCTX_SANDBOX_ENGINE", Some("envengine")),
                ("WLSCTX_SOCKET_PATH", Some("/env/socket")),
            ],
            || {
                let args = parse_wayland(&[
                    "wlsctx",
                    "wayland",
                    "--listen",
                    "/run/wlsctx/wayland-1",
                    "--app-id",
                    "flagapp",
                ])
                .expect("flag + env mix must parse");
                // CLI wins for the flag that was given explicitly…
                assert_eq!(
                    args.listen.as_deref(),
                    Some(std::path::Path::new("/run/wlsctx/wayland-1"))
                );
                assert_eq!(args.app_id, "flagapp");
                // …and env still fills the arguments that were not given.
                assert_eq!(args.instance_id, "envinst");
                assert_eq!(args.sandbox_engine, "envengine");
                assert!(!args.socket_activation);
            },
        );
    }

    #[test]
    fn wayland_requires_sandbox_engine() {
        without_wlsctx_env(|| {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
            ])
            .expect_err("sandbox_engine is always required (no default)");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
            assert!(err.to_string().contains("--sandbox-engine"));
        });
    }

    #[test]
    fn wayland_listen_given_twice_is_rejected() {
        // clap models a repeated single-value flag as the argument
        // conflicting with itself (ArgAction::Set does not override
        // itself unless `args_override_self` is set): the second
        // --listen is an error, it never silently wins.
        without_wlsctx_env(|| {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--listen",
                "/other/socket",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect_err("--listen must not be repeatable");
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        });
    }

    #[test]
    fn wayland_socket_activation_conflicts_with_socket_path_env() {
        // WLSCTX_SOCKET_PATH in the environment counts as --listen being
        // present for clap's conflict check, so a stray env var (e.g. left
        // over from a shell) makes mode A refuse to start instead of
        // silently ignoring the path.
        with_env(
            &[("WLSCTX_SOCKET_PATH", Some("/run/wlsctx/wayland-1"))],
            || {
                let err = parse_wayland(&[
                    "wlsctx",
                    "wayland",
                    "--socket-activation",
                    "--app-id",
                    "a",
                    "--instance-id",
                    "i",
                    "--sandbox-engine",
                    "wlsctx",
                ])
                .expect_err("--socket-activation must conflict with an env-provided --listen");
                assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
            },
        );
    }

    #[test]
    fn wayland_empty_env_values_are_rejected() {
        // An *empty* WLSCTX_* variable is a value for clap, not "unset"
        // (a common environment.d typo). It used to be accepted, which
        // tagged the socket with an empty ID matching no compositor
        // policy and silently disabled the sandbox: each ID is now
        // rejected at parse time.
        let valid: [(&str, &str); 3] = [
            ("WLSCTX_APP_ID", "a"),
            ("WLSCTX_INSTANCE_ID", "i"),
            ("WLSCTX_SANDBOX_ENGINE", "wlsctx"),
        ];
        for (target, field) in [
            ("WLSCTX_APP_ID", "--app-id"),
            ("WLSCTX_INSTANCE_ID", "--instance-id"),
            ("WLSCTX_SANDBOX_ENGINE", "--sandbox-engine"),
        ] {
            let pairs: Vec<(&str, Option<&str>)> = valid
                .iter()
                .map(|(name, value)| (*name, Some(if *name == target { "" } else { *value })))
                .chain(std::iter::once((
                    "WLSCTX_SOCKET_PATH",
                    Some("/run/wlsctx/wayland-1"),
                )))
                .collect();
            with_env(&pairs, || {
                let err = parse_wayland(&["wlsctx", "wayland"])
                    .expect_err("an empty WLSCTX_* value must be rejected at parse time");
                assert_eq!(ErrorKind::InvalidValue, err.kind(), "{target}");
                let msg = err.to_string();
                assert!(msg.contains(field), "{target}: {msg}");
                assert!(msg.contains("not be empty"), "{target}: {msg}");
            });
        }
    }

    #[test]
    fn wayland_empty_flag_values_are_rejected() {
        // The same guard applies to explicit flags (`--app-id ""`).
        without_wlsctx_env(|| {
            let fields: [(&str, &str); 3] = [
                ("--app-id", "a"),
                ("--instance-id", "i"),
                ("--sandbox-engine", "wlsctx"),
            ];
            for (flag, _valid) in fields {
                let mut argv: Vec<&str> =
                    vec!["wlsctx", "wayland", "--listen", "/run/wlsctx/wayland-1"];
                for (f, v) in fields {
                    argv.push(f);
                    argv.push(if f == flag { "" } else { v });
                }
                let err = parse_wayland(&argv).expect_err("an empty flag value must be rejected");
                assert_eq!(ErrorKind::InvalidValue, err.kind(), "{flag}");
                let msg = err.to_string();
                assert!(msg.contains(flag), "{msg}");
                assert!(msg.contains("not be empty"), "{msg}");
            }
        });
    }

    #[test]
    fn run_requires_a_command() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from(["wlsctx", "run"]).expect_err(
                "`run` without a command must be rejected (a trailing arg is required)",
            );
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
        });
    }

    #[test]
    fn run_parses_the_command_after_dashes() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from(["wlsctx", "run", "--", "/bin/sh", "-c", "id"])
                .expect("ad-hoc run with `--` must parse");
            let Command::Run(args) = cli.command else {
                unreachable!();
            };
            assert_eq!(
                args.command,
                vec![
                    std::ffi::OsString::from("/bin/sh"),
                    std::ffi::OsString::from("-c"),
                    std::ffi::OsString::from("id"),
                ]
            );
        });
    }

    #[test]
    fn run_parses_a_command_without_explicit_dashes() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from(["wlsctx", "run", "/usr/bin/id", "-u"])
                .expect("ad-hoc run without `--` must parse when all trailing values");
            let Command::Run(args) = cli.command else {
                unreachable!();
            };
            assert_eq!(
                args.command,
                vec![
                    std::ffi::OsString::from("/usr/bin/id"),
                    std::ffi::OsString::from("-u"),
                ]
            );
        });
    }

    #[test]
    fn run_flags_after_the_command_are_values_not_flags() {
        without_wlsctx_env(|| {
            // After the command starts, `--listen` belongs to the
            // command, not to wlsctx: the command runs with it intact.
            let cli = Cli::try_parse_from(["wlsctx", "run", "--", "/usr/bin/sleep", "--listen"])
                .expect("a flag-like token after `--` is part of the command");
            let Command::Run(args) = cli.command else {
                unreachable!();
            };
            assert_eq!(
                args.command,
                vec![
                    std::ffi::OsString::from("/usr/bin/sleep"),
                    std::ffi::OsString::from("--listen"),
                ]
            );
        });
    }

    #[test]
    fn run_defaults_for_identity_and_network() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from(["wlsctx", "run", "--", "/bin/sh", "-c", "id"])
                .expect("ad-hoc run must parse with the default identity");
            let Command::Run(args) = cli.command else {
                unreachable!();
            };
            assert_eq!(args.app_id, "app");
            assert_eq!(args.instance_id, "1");
            assert_eq!(args.network, "shared");
        });
    }

    #[test]
    fn run_network_rejects_unknown_modes() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from(["wlsctx", "run", "--network", "veth", "--", "/bin/sh"])
                .expect_err("an unknown network mode must be rejected at parse time");
            assert_eq!(err.kind(), ErrorKind::InvalidValue);
        });
    }

    #[test]
    fn run_rejects_wlsctx_flags_before_the_command() {
        without_wlsctx_env(|| {
            // A flag *before* the command (no `--` separator) that
            // `run` does not know must be rejected, not silently
            // routed into the command.
            let err = Cli::try_parse_from(["wlsctx", "run", "--no-such-flag", "/bin/sh"])
                .expect_err("an unknown flag before the command must be rejected");
            assert_eq!(err.kind(), ErrorKind::UnknownArgument);
        });
    }

    // -----------------------------------------------------------------
    // Proxy mode (wayland --proxy): ported from the flat-CLI tests of
    // the clipboard branch, adapted to the subcommand structure.
    // -----------------------------------------------------------------

    #[test]
    fn wayland_proxy_requires_tagged_socket() {
        without_wlsctx_env(|| {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect_err("--proxy requires --tagged-socket");
            assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
            assert!(err.to_string().contains("--tagged-socket"), "{err}");
        });
    }

    #[test]
    fn wayland_proxy_parses_with_tagged_socket() {
        without_wlsctx_env(|| {
            let args = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/run/user/1000/wlsctx-tagged",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("proxy mode with a tagged socket must parse");
            assert!(args.proxy);
            assert_eq!(
                args.tagged_socket.as_deref(),
                Some(std::path::Path::new("/run/user/1000/wlsctx-tagged"))
            );
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/run/user/1000/wlsctx-tagged",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("proxy mode validates");
            cli.validate().expect("proxy mode validates");
        });
    }

    #[test]
    fn wayland_notify_copy_out_requires_proxy_and_broker_socket() {
        without_wlsctx_env(|| {
            // Without --proxy.
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--notify-copy-out",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("clap cannot express 'only with --proxy'; validate() catches it");
            let err = cli
                .validate()
                .expect_err("--notify-copy-out without --proxy must be rejected");
            assert!(err.to_string().contains("--proxy"), "{err}");

            // With --proxy but no --broker-socket: the notification
            // has nowhere to travel.
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/tmp/t",
                "--notify-copy-out",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("clap cannot express 'needs --broker-socket'; validate() catches it");
            let err = cli
                .validate()
                .expect_err("--notify-copy-out without --broker-socket must be rejected");
            assert!(err.to_string().contains("--broker-socket"), "{err}");

            // With both: valid.
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/tmp/t",
                "--broker-socket",
                "/tmp/broker.sock",
                "--notify-copy-out",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("notify-copy-out with --proxy and --broker-socket must parse");
            cli.validate()
                .expect("notify-copy-out with both flags validates");
        });
    }

    #[test]
    fn wayland_clipboard_policy_defaults_to_allow_and_accepts_deny() {
        without_wlsctx_env(|| {
            let base = [
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/tmp/t",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ];
            // Default.
            let args = parse_wayland(&base).expect("the default policy must parse");
            assert_eq!(args.clipboard_policy, "allow");
            let cli = Cli::try_parse_from(base).expect("the default policy validates");
            cli.validate().expect("the default policy validates");
            // Explicit deny in proxy mode is fine.
            let mut argv: Vec<&str> = base.to_vec();
            argv.extend(["--clipboard-policy", "deny"]);
            let args = parse_wayland(&argv).expect("an explicit deny must parse");
            assert_eq!(args.clipboard_policy, "deny");
            let cli = Cli::try_parse_from(argv).expect("an explicit deny validates");
            cli.validate().expect("an explicit deny validates");
        });
    }

    #[test]
    fn wayland_clipboard_policy_deny_requires_proxy() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--clipboard-policy",
                "deny",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("clap cannot test a flag's value against another flag; validate() does");
            let err = cli
                .validate()
                .expect_err("--clipboard-policy deny without --proxy must be rejected");
            assert!(err.to_string().contains("--proxy"), "{err}");
        });
    }

    #[test]
    fn wayland_invalid_clipboard_policy_is_rejected() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--proxy",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/tmp/t",
                "--clipboard-policy",
                "sometimes",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("the value is free text at parse time; validate() checks it");
            let err = cli
                .validate()
                .expect_err("an unknown policy value must be rejected");
            assert!(err.to_string().contains("sometimes"), "{err}");
        });
    }

    #[test]
    fn wayland_tagged_socket_without_proxy_is_rejected() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "wayland",
                "--listen",
                "/run/wlsctx/wayland-1",
                "--tagged-socket",
                "/somewhere",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "wlsctx",
            ])
            .expect("clap cannot express 'only with --proxy'; validate() catches it");
            let err = cli
                .validate()
                .expect_err("--tagged-socket without --proxy must be rejected");
            assert!(err.to_string().contains("--proxy"), "{err}");
        });
    }

    // -----------------------------------------------------------------
    // Broker and decide subcommands (ported from the flat-CLI tests).
    // -----------------------------------------------------------------

    #[test]
    fn decide_parses_without_listen() {
        // The decider is a one-shot client of the broker's decision
        // socket: it never binds one, so nothing is required at all.
        without_wlsctx_env(|| {
            let args = parse_decide(&["wlsctx", "decide"]).expect("decide needs no listen socket");
            assert!(args.decision.is_none());
            assert!(args.prompt.is_none());
            let cli = Cli::try_parse_from(["wlsctx", "decide"])
                .expect("decide mode parses without a listen socket");
            cli.validate()
                .expect("decide mode validates without a listen socket");
        });
    }

    #[test]
    fn decide_decision_requires_a_valid_keyword() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from(["wlsctx", "decide", "--decision", "sometimes"])
                .expect("the keyword is free text at parse time; validate() checks it");
            let err = cli
                .validate()
                .expect_err("an unknown decision keyword must be rejected");
            assert!(err.to_string().contains("sometimes"), "{err}");

            for d in ["allow", "deny"] {
                let args = parse_decide(&["wlsctx", "decide", "--decision", d])
                    .expect("a valid keyword must parse");
                assert_eq!(args.decision.as_deref(), Some(d));
                let cli = Cli::try_parse_from(["wlsctx", "decide", "--decision", d])
                    .expect("a valid keyword must validate");
                cli.validate().expect("a valid keyword must validate");
            }
        });
    }

    #[test]
    fn decide_prompt_is_an_optional_id() {
        without_wlsctx_env(|| {
            let args =
                parse_decide(&["wlsctx", "decide", "--prompt", "3"]).expect("--prompt must parse");
            assert_eq!(args.prompt, Some(3));
        });
    }

    #[test]
    fn broker_requires_listen_without_socket_activation() {
        // --listen is optional at parse time (the runtime check in
        // run_broker is the one that fails), but the conflict with
        // --socket-activation is enforced by clap.
        without_wlsctx_env(|| {
            let err = parse_broker(&[
                "wlsctx",
                "broker",
                "--socket-activation",
                "--listen",
                "/run/user/1000/wlsctx-broker.sock",
            ])
            .expect_err("--socket-activation and --listen must conflict");
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        });
    }

    #[test]
    fn broker_auto_decide_requires_a_valid_keyword() {
        without_wlsctx_env(|| {
            let cli = Cli::try_parse_from([
                "wlsctx",
                "broker",
                "--listen",
                "/run/user/1000/wlsctx-broker.sock",
                "--auto-decide",
                "sometimes",
            ])
            .expect("the keyword is free text at parse time; validate() checks it");
            let err = cli
                .validate()
                .expect_err("an unknown auto-decide keyword must be rejected");
            assert!(err.to_string().contains("sometimes"), "{err}");

            let args = parse_broker(&[
                "wlsctx",
                "broker",
                "--listen",
                "/run/user/1000/wlsctx-broker.sock",
                "--auto-decide",
                "allow",
                "--broker-timeout-millis",
                "1000",
            ])
            .expect("a valid auto-decide must parse");
            assert_eq!(args.auto_decide.as_deref(), Some("allow"));
            assert_eq!(args.broker_timeout_millis, 1000);
            let cli = Cli::try_parse_from([
                "wlsctx",
                "broker",
                "--listen",
                "/run/user/1000/wlsctx-broker.sock",
                "--auto-decide",
                "allow",
            ])
            .expect("a valid auto-decide must validate");
            cli.validate().expect("a valid auto-decide must validate");
        });
    }

    #[test]
    fn broker_timeout_defaults_to_thirty_seconds() {
        without_wlsctx_env(|| {
            let args = parse_broker(&[
                "wlsctx",
                "broker",
                "--listen",
                "/run/user/1000/wlsctx-broker.sock",
            ])
            .expect("the default timeout must parse");
            assert_eq!(args.broker_timeout_millis, 30_000);
        });
    }
}
