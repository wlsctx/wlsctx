//! Command-line interface.
//!
//! A subcommand tree (PLAN.md §5): `wayland` is the original
//! single-mode behaviour (a tagged Wayland socket), and `run` is the
//! sandboxed-execution path (ad-hoc for now; profile-driven in later
//! phases).

use clap::builder::TypedValueParser;
use clap::{Args, Parser, Subcommand};
use std::ffi::{OsStr, OsString};
use std::path;

/// wlsctx: run commands inside a namespaced, landlock+seccomp
/// confined sandbox, or tag a Wayland socket with a security context
/// so the compositor can identify sandboxed clients.
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
    ///
    /// See https://wayland.app/protocols/security-context-v1
    Wayland(WaylandArgs),
}

/// Arguments of `wlsctx run`.
#[derive(Args, Debug)]
pub(crate) struct RunArgs {
    /// Command and its arguments, run inside the sandbox
    /// (everything after `--`; e.g. `wlsctx run -- /bin/sh -c 'id'`)
    #[arg(trailing_var_arg = true, required = true)]
    pub(crate) command: Vec<OsString>,
}

/// Arguments of `wlsctx wayland` (the original single-mode CLI).
#[derive(Args, Debug)]
pub(crate) struct WaylandArgs {
    /// Application ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_APP_ID", value_parser = NonEmpty::new("app-id"))]
    pub(crate) app_id: String,
    /// Instance ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_INSTANCE_ID", value_parser = NonEmpty::new("instance-id"))]
    pub(crate) instance_id: String,
    /// Sandbox engine ID in security context (must not be empty)
    #[arg(long, env = "WLSCTX_SANDBOX_ENGINE", value_parser = NonEmpty::new("sandbox-engine"))]
    pub(crate) sandbox_engine: String,
    /// Listen on Unix socket
    #[arg(
        long,
        env = "WLSCTX_SOCKET_PATH",
        required_unless_present = "socket_activation"
    )]
    pub(crate) listen: Option<path::PathBuf>,
    /// Receive socket via systemd socket activation (LISTEN_FDS)
    #[arg(long, conflicts_with = "listen")]
    pub(crate) socket_activation: bool,
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
    use super::{Cli, Command, WaylandArgs};
    use crate::testutil::{with_env, without_wlsctx_env};
    use clap::error::ErrorKind;
    use clap::Parser;

    /// Parse in `wayland` subcommand form and extract the args.
    fn parse_wayland(argv: &[&str]) -> Result<WaylandArgs, clap::Error> {
        let cli = Cli::try_parse_from(argv)?;
        Ok(match cli.command {
            Command::Wayland(args) => args,
            _ => unreachable!("parse_wayland must only parse the wayland subcommand"),
        })
    }

    #[test]
    fn parses_explicit_arguments() {
        without_wlsctx_env(|| {
            let args = parse_wayland(&[
                "wlsctx",
                "wayland",
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
                args.listen.as_deref(),
                Some(std::path::Path::new("/run/pod/wayland-1"))
            );
            assert_eq!(args.app_id, "rustrover");
            assert_eq!(args.instance_id, "work");
            assert_eq!(args.sandbox_engine, "podman");
            assert!(!args.socket_activation);
        });
    }

    #[test]
    fn requires_subcommand() {
        without_wlsctx_env(|| {
            let err = Cli::try_parse_from(["wlsctx"])
                .expect_err("a subcommand is required");
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
            let err = Cli::try_parse_from(["wlsctx", "podman"])
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
                "podman",
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
                "/run/pod/wayland-1",
                "--sandbox-engine",
                "podman",
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
                "/run/pod/wayland-1",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
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
                "podman",
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
                "podman",
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
                ("WLSCTX_SOCKET_PATH", Some("/run/pod/wayland-1")),
            ],
            || {
                let args =
                    parse_wayland(&["wlsctx", "wayland"]).expect("env vars satisfy all args");
                assert_eq!(args.app_id, "envapp");
                assert_eq!(args.instance_id, "envinst");
                assert_eq!(args.sandbox_engine, "envengine");
                assert_eq!(
                    args.listen.as_deref(),
                    Some(std::path::Path::new("/run/pod/wayland-1"))
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
                    "/run/pod/wayland-1",
                    "--app-id",
                    "flagapp",
                ])
                .expect("flag + env mix must parse");
                // CLI wins for the flag that was given explicitly…
                assert_eq!(
                    args.listen.as_deref(),
                    Some(std::path::Path::new("/run/pod/wayland-1"))
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
                "/run/pod/wayland-1",
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
                "/run/pod/wayland-1",
                "--listen",
                "/other/socket",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
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
        with_env(&[("WLSCTX_SOCKET_PATH", Some("/run/pod/wayland-1"))], || {
            let err = parse_wayland(&[
                "wlsctx",
                "wayland",
                "--socket-activation",
                "--app-id",
                "a",
                "--instance-id",
                "i",
                "--sandbox-engine",
                "podman",
            ])
            .expect_err("--socket-activation must conflict with an env-provided --listen");
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        });
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
            ("WLSCTX_SANDBOX_ENGINE", "podman"),
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
                    Some("/run/pod/wayland-1"),
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
                ("--sandbox-engine", "podman"),
            ];
            for (flag, _valid) in fields {
                let mut argv: Vec<&str> =
                    vec!["wlsctx", "wayland", "--listen", "/run/pod/wayland-1"];
                for (f, v) in fields {
                    argv.push(f);
                    argv.push(if f == flag { "" } else { v });
                }
                let err = parse_wayland(&argv)
                    .expect_err("an empty flag value must be rejected");
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
            let cli = Cli::try_parse_from([
                "wlsctx",
                "run",
                "--",
                "/usr/bin/sleep",
                "--listen",
            ])
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
    fn run_rejects_wlsctx_flags_before_the_command() {
        without_wlsctx_env(|| {
            // A wlsctx flag *before* the command (no `--` separator) is
            // parsed in the `run` context, which has no flags of its
            // own: `--listen` (a `wayland` flag) must be rejected, not
            // silently routed into the command.
            let err = Cli::try_parse_from(["wlsctx", "run", "--listen", "/bin/sh"])
                .expect_err("a wlsctx flag before the command must be rejected");
            assert_eq!(err.kind(), ErrorKind::UnknownArgument);
        });
    }
}
