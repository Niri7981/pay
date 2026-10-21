//! Program status reports (OSC 7501).
//!
//! Tells the terminal that pay is waiting on the user while an auth prompt
//! is up, so tabs, panes and notifications can surface it. Spec:
//! <https://www.superlogical.com/rex/docs/build/program-status>.
//!
//! Reports go to stderr, and only when stderr is a terminal: stdout may be
//! piped JSON or an MCP stdio transport. Terminals ignore unknown OSCs, so
//! no capability query is needed.

use std::io::{IsTerminal, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::AuthIntent;

const APP: &str = "pay";

/// Why the program is blocked, as the spec's `kind` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockedKind {
    /// Approving an action (a payment, a session, a fee payer).
    Permission,
    /// Proving identity to manage an account.
    Auth,
}

impl BlockedKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Permission => "permission",
            Self::Auth => "auth",
        }
    }
}

fn describe(intent: &AuthIntent) -> (BlockedKind, &'static str) {
    match intent {
        AuthIntent::AuthorizePayment { .. } => (BlockedKind::Permission, "Approve payment"),
        AuthIntent::AuthorizeBatch { .. } => (BlockedKind::Permission, "Approve batch payment"),
        AuthIntent::OpenSession(_) => (BlockedKind::Permission, "Approve payment session"),
        AuthIntent::UseGatewayFeePayer(_) => (BlockedKind::Permission, "Approve gasless payment"),
        AuthIntent::CreateAccount(_) => (BlockedKind::Auth, "Authenticate to create account"),
        AuthIntent::ImportAccount(_) => (BlockedKind::Auth, "Authenticate to import account"),
        AuthIntent::ExportAccount(_) => (BlockedKind::Auth, "Authenticate to export account"),
        AuthIntent::DeleteAccount(_) => (BlockedKind::Auth, "Authenticate to delete account"),
        AuthIntent::UseAccount(_) => (BlockedKind::Auth, "Authenticate to use account"),
        AuthIntent::SignIn(_) => (BlockedKind::Permission, "Approve wallet sign-in"),
    }
}

fn blocked_report(intent: &AuthIntent) -> String {
    let (kind, msg) = describe(intent);
    format!(
        "\x1b]7501;state=blocked:kind={}:app={APP}:msg={}\x1b\\",
        kind.as_str(),
        STANDARD.encode(msg)
    )
}

fn clear_report() -> String {
    "\x1b]7501;state=clear\x1b\\".to_string()
}

fn enabled() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}

fn emit(report: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(report.as_bytes());
    let _ = stderr.flush();
}

/// Reports `blocked` while alive and clears the record on drop, so the
/// terminal stops flagging pay whether the prompt succeeds or fails.
pub(crate) struct Blocked {
    active: bool,
}

impl Blocked {
    pub(crate) fn new(intent: &AuthIntent) -> Self {
        let active = enabled();
        if active {
            emit(&blocked_report(intent));
        }
        Self { active }
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        if self.active {
            emit(&clear_report());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_prompt_reports_blocked_permission() {
        let report = blocked_report(&AuthIntent::authorize_payment("$0.05", "api.example.com"));
        assert_eq!(
            report,
            "\x1b]7501;state=blocked:kind=permission:app=pay:msg=QXBwcm92ZSBwYXltZW50\x1b\\"
        );
    }

    #[test]
    fn account_prompt_reports_blocked_auth() {
        let report = blocked_report(&AuthIntent::ExportAccount("export".to_string()));
        assert!(report.contains("state=blocked:kind=auth:app=pay:msg="));
    }

    #[test]
    fn reports_stay_within_the_spec_charset() {
        let intents = [
            AuthIntent::authorize_payment("$1.00", "x"),
            AuthIntent::OpenSession(String::new()),
            AuthIntent::UseGatewayFeePayer(String::new()),
            AuthIntent::CreateAccount(String::new()),
            AuthIntent::ImportAccount(String::new()),
            AuthIntent::DeleteAccount(String::new()),
            AuthIntent::UseAccount(String::new()),
        ];
        for intent in intents {
            let report = blocked_report(&intent);
            let body = report
                .strip_prefix("\x1b]7501;")
                .and_then(|r| r.strip_suffix("\x1b\\"))
                .expect("framed as OSC 7501 ... ST");
            for pair in body.split(':') {
                let (key, value) = pair.split_once('=').expect("key=value");
                assert!(key.chars().all(|c| c.is_ascii_lowercase()));
                assert!(
                    value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.,+/=-".contains(c)),
                    "{value}"
                );
            }
        }
    }

    #[test]
    fn clear_addresses_the_root_record() {
        assert_eq!(clear_report(), "\x1b]7501;state=clear\x1b\\");
    }
}
