//! The MCP hosts that connect to pay-connect, and how each one authenticates.
//!
//! Every host is an OAuth client of this server, so the protocol is one:
//! discovery, registration, PKCE, tokens. What differs per host is the
//! shape around it: which redirect URIs it registers (a custom scheme for
//! a desktop app, a fixed HTTPS callback for a web host, loopback for a
//! CLI), and the quirks that decide whether the flow can finish at all.
//! Those live here as data, so adding a host is one entry and the OAuth
//! server never grows a special case.
//!
//! Redirect policy: `https://` anywhere and `http://` on loopback are
//! always allowed (RFC 8252). A custom scheme is allowed only when a
//! profile lists it, since an unknown scheme could belong to anything on
//! the user's machine.

use url::Url;

/// One kind of redirect URI a host registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirect {
    /// This exact URI.
    Exact(&'static str),
    /// Any URI starting with this (hosts that mint a per-connector path).
    Prefix(&'static str),
    /// `http://localhost:<any port><path>` or `127.0.0.1`; CLIs and desktop
    /// apps bind an ephemeral port.
    Loopback { path: &'static str },
    /// A custom scheme such as `cursor://…`, allowed only because a known
    /// host uses it.
    Scheme(&'static str),
}

impl Redirect {
    fn matches(self, url: &Url) -> bool {
        match self {
            Redirect::Exact(exact) => {
                url.as_str().trim_end_matches('/') == exact.trim_end_matches('/')
            }
            Redirect::Prefix(prefix) => url.as_str().starts_with(prefix),
            Redirect::Loopback { path } => is_loopback(url) && url.path() == path,
            Redirect::Scheme(scheme) => url.scheme() == scheme,
        }
    }
}

/// What a host can and cannot do, as observed. Informational for the
/// consent page and the logs; the OAuth server behaves the same for all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quirks {
    /// Registers itself with RFC 7591 rather than needing a pre-issued id.
    pub dynamic_registration: bool,
    /// Can attach a static `Authorization` header from its configuration.
    pub static_header: bool,
    /// Has been seen finishing the authorization-code flow end to end.
    pub completes_oauth: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProfile {
    pub id: &'static str,
    pub display_name: &'static str,
    /// `client_name` values the host registers under.
    client_names: &'static [&'static str],
    redirects: &'static [Redirect],
    pub quirks: Quirks,
}

impl HostProfile {
    /// Whether a code sent to `uri` stays with this host: one of its own
    /// callbacks, or loopback on the user's machine.
    fn accepts_redirect(&self, uri: &Url) -> bool {
        is_loopback(uri) || self.redirects.iter().any(|r| r.matches(uri))
    }

    /// A name or callback claims a profile only when every registered
    /// callback belongs to it; a known name beside a foreign callback is
    /// generic.
    fn claims(&self, client_name: Option<&str>, redirect_uris: &[Url]) -> bool {
        if redirect_uris.is_empty() || !redirect_uris.iter().all(|u| self.accepts_redirect(u)) {
            return false;
        }
        let by_name = client_name
            .map(|n| {
                self.client_names
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(n.trim()))
            })
            .unwrap_or(false);
        let by_redirect = redirect_uris.iter().any(|u| {
            self.redirects
                .iter()
                .any(|r| !matches!(r, Redirect::Loopback { .. }) && r.matches(u))
        });
        by_name || by_redirect
    }
}

/// The hosts pay-connect knows, in the order they are tried. A host that
/// matches none is `GENERIC`, served exactly like the others.
pub static HOSTS: &[HostProfile] = &[
    HostProfile {
        id: "grok",
        display_name: "Grok",
        client_names: &["Grok"],
        redirects: &[
            Redirect::Exact("https://grok.com/connectors-oauth-exchange-code/"),
            Redirect::Exact("https://grok.com/connectors/oauth/callback"),
        ],
        // Observed 2026-09-17: registers, then never opens the
        // authorization endpoint, and sends no header from its dialog.
        quirks: Quirks {
            dynamic_registration: true,
            static_header: false,
            completes_oauth: false,
        },
    },
    HostProfile {
        id: "claude",
        display_name: "Claude",
        client_names: &["Claude", "claude.ai", "Claude Web"],
        redirects: &[Redirect::Exact("https://claude.ai/api/mcp/auth_callback")],
        quirks: Quirks {
            dynamic_registration: true,
            static_header: false,
            completes_oauth: true,
        },
    },
    HostProfile {
        id: "chatgpt",
        display_name: "ChatGPT",
        client_names: &["ChatGPT", "OpenAI", "Codex"],
        redirects: &[
            Redirect::Exact("https://chatgpt.com/connector_platform_oauth_redirect"),
            Redirect::Prefix("https://chatgpt.com/connector/oauth/"),
        ],
        quirks: Quirks {
            dynamic_registration: true,
            static_header: false,
            completes_oauth: true,
        },
    },
    HostProfile {
        id: "cursor",
        display_name: "Cursor",
        client_names: &["Cursor", "Cursor Agents"],
        redirects: &[
            Redirect::Exact("https://www.cursor.com/agents/mcp/oauth/callback"),
            Redirect::Scheme("cursor"),
        ],
        quirks: Quirks {
            dynamic_registration: true,
            static_header: true,
            completes_oauth: true,
        },
    },
    HostProfile {
        id: "claude-code",
        display_name: "Claude Code",
        client_names: &["Claude Code", "claude-code"],
        redirects: &[
            Redirect::Loopback { path: "/callback" },
            // Claude Desktop through mcp-remote.
            Redirect::Loopback {
                path: "/oauth/callback",
            },
        ],
        quirks: Quirks {
            dynamic_registration: true,
            static_header: true,
            completes_oauth: true,
        },
    },
    HostProfile {
        id: "codex",
        display_name: "Codex CLI",
        client_names: &["Codex CLI", "codex"],
        redirects: &[Redirect::Loopback {
            path: "/auth/callback",
        }],
        quirks: Quirks {
            dynamic_registration: true,
            static_header: true,
            completes_oauth: true,
        },
    },
];

/// Any other public client.
pub static GENERIC: HostProfile = HostProfile {
    id: "generic",
    display_name: "An MCP client",
    client_names: &[],
    redirects: &[],
    quirks: Quirks {
        dynamic_registration: true,
        static_header: false,
        completes_oauth: true,
    },
};

fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http"
        && matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("[::1]")
        )
}

/// Whether a host may register `uri` as a redirect.
pub fn redirect_allowed(uri: &str) -> Result<Url, &'static str> {
    let url = Url::parse(uri).map_err(|_| "not a URL")?;
    if url.fragment().is_some() {
        return Err("must not have a fragment");
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback(&url) => Ok(url),
        "http" => Err("http is only allowed on loopback"),
        scheme => {
            let known = HOSTS
                .iter()
                .flat_map(|h| h.redirects.iter())
                .any(|r| matches!(r, Redirect::Scheme(s) if *s == scheme));
            if known {
                Ok(url)
            } else {
                Err("custom schemes are only allowed for known hosts")
            }
        }
    }
}

/// The profile a registration belongs to, by name or by redirect URI.
/// Loopback redirects are too generic to identify a host on their own.
pub fn identify(client_name: Option<&str>, redirect_uris: &[String]) -> &'static HostProfile {
    let urls: Vec<Url> = redirect_uris
        .iter()
        .filter_map(|u| Url::parse(u).ok())
        .collect();
    HOSTS
        .iter()
        .find(|h| h.claims(client_name, &urls))
        .unwrap_or(&GENERIC)
}

pub fn by_id(id: &str) -> &'static HostProfile {
    HOSTS.iter().find(|h| h.id == id).unwrap_or(&GENERIC)
}

/// The profile `host_id` names, only if `redirect_uri` is bound to it.
pub fn verified(host_id: &str, redirect_uri: &str) -> &'static HostProfile {
    let host = by_id(host_id);
    match Url::parse(redirect_uri) {
        Ok(url) if host.accepts_redirect(&url) => host,
        _ => &GENERIC,
    }
}

/// Whether `name` is what a known host calls itself, so showing it for an
/// unverified client would impersonate that host.
pub fn names_known_host(name: &str) -> bool {
    let name = name.trim();
    HOSTS.iter().any(|h| {
        h.display_name.eq_ignore_ascii_case(name)
            || h.id.eq_ignore_ascii_case(name)
            || h.client_names.iter().any(|c| c.eq_ignore_ascii_case(name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn known_hosts_are_recognised_by_redirect_or_name() {
        assert_eq!(
            identify(
                None,
                &uris(&["https://grok.com/connectors-oauth-exchange-code/"])
            )
            .id,
            "grok"
        );
        assert_eq!(
            identify(
                Some("grok"),
                &uris(&["https://grok.com/connectors/oauth/callback"])
            )
            .id,
            "grok",
            "name match is case-insensitive"
        );
        assert_eq!(
            identify(Some("grok"), &uris(&["http://127.0.0.1:4000/cb"])).id,
            "grok",
            "loopback keeps the code on the user's machine"
        );
        assert_eq!(
            identify(None, &uris(&["https://claude.ai/api/mcp/auth_callback"])).id,
            "claude"
        );
        assert_eq!(
            identify(None, &uris(&["https://chatgpt.com/connector/oauth/abc123"])).id,
            "chatgpt"
        );
        assert_eq!(
            identify(
                Some("Anysphere"),
                &uris(&[
                    "cursor://anysphere.cursor-mcp/oauth/callback",
                    "http://localhost:8787/callback"
                ])
            )
            .id,
            "cursor"
        );
        assert_eq!(
            identify(
                Some("Codex CLI"),
                &uris(&["http://localhost:1455/auth/callback"])
            )
            .id,
            "codex"
        );
        // Loopback alone does not name a host.
        assert_eq!(
            identify(None, &uris(&["http://localhost:3000/callback"])).id,
            "generic"
        );
        assert_eq!(
            identify(Some("Some Agent"), &uris(&["https://agent.example/cb"])).id,
            "generic"
        );
        assert_eq!(by_id("claude").display_name, "Claude");
        assert_eq!(by_id("nope").id, "generic");
    }

    #[test]
    fn known_names_beside_foreign_callbacks_are_generic() {
        for name in ["ChatGPT", "Claude", "grok", "Cursor", "Claude Code"] {
            assert_eq!(
                identify(Some(name), &uris(&["https://attacker.example/callback"])).id,
                "generic",
                "{name}"
            );
        }
        // One foreign callback among genuine ones still taints the set.
        assert_eq!(
            identify(
                Some("ChatGPT"),
                &uris(&[
                    "https://chatgpt.com/connector_platform_oauth_redirect",
                    "https://attacker.example/callback"
                ])
            )
            .id,
            "generic"
        );
        // Lookalike origins do not match an exact or prefix callback.
        for uri in [
            "https://chatgpt.com.attacker.example/connector/oauth/x",
            "https://claude.ai.attacker.example/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback/../../evil",
        ] {
            assert_eq!(identify(None, &uris(&[uri])).id, "generic", "{uri}");
        }
        assert_eq!(identify(Some("ChatGPT"), &[]).id, "generic");
    }

    #[test]
    fn verified_binds_the_profile_to_the_chosen_callback() {
        assert_eq!(
            verified("claude", "https://claude.ai/api/mcp/auth_callback").id,
            "claude"
        );
        assert_eq!(verified("claude", "http://localhost:9/cb").id, "claude");
        assert_eq!(
            verified("claude", "https://attacker.example/callback").id,
            "generic"
        );
        assert_eq!(verified("claude", "not a url").id, "generic");
        assert_eq!(
            verified("generic", "https://agent.example/cb").id,
            "generic"
        );
        assert!(names_known_host(" chatgpt ") && names_known_host("Claude Web"));
        assert!(!names_known_host("Some Agent"));
    }

    #[test]
    fn redirect_policy() {
        assert!(redirect_allowed("https://grok.com/cb").is_ok());
        assert!(redirect_allowed("http://localhost:3000/cb").is_ok());
        assert!(redirect_allowed("http://127.0.0.1:1455/auth/callback").is_ok());
        assert!(redirect_allowed("http://[::1]:3000/cb").is_ok());
        assert!(
            redirect_allowed("cursor://anysphere.cursor-mcp/oauth/callback").is_ok(),
            "a known host's scheme"
        );
        assert_eq!(
            redirect_allowed("grokbot://callback").unwrap_err(),
            "custom schemes are only allowed for known hosts"
        );
        assert_eq!(
            redirect_allowed("http://grok.com/cb").unwrap_err(),
            "http is only allowed on loopback"
        );
        assert!(redirect_allowed("https://grok.com/cb#frag").is_err());
        assert!(redirect_allowed("nope").is_err());
    }

    #[test]
    fn grok_is_marked_as_not_finishing_oauth() {
        assert!(!by_id("grok").quirks.completes_oauth);
        assert!(by_id("claude").quirks.completes_oauth);
    }
}
