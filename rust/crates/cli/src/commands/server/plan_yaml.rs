//! Line-based rewrite of `subscription:` blocks in a spec YAML, keyed by the
//! endpoint's [`PlanRoute`]. Preserves comments and key order, which a
//! `serde_yml` round-trip would strip.

use std::collections::{HashMap, HashSet};

use pay_core::server::subscription::PlanRoute;
use pay_types::metering::HttpMethod;

/// Fields to (re)write under one route's `subscription:` block.
pub(crate) type SubscriptionFields = Vec<(&'static str, String)>;

/// Rewrite each listed route's `subscription:` block: drop any existing line
/// for a listed key, then append the new values at the end of the block.
///
/// Returns the routes that could not be located in the YAML.
pub(crate) fn rewrite_subscription_fields(
    yaml: &str,
    updates: &HashMap<PlanRoute, SubscriptionFields>,
) -> (String, Vec<PlanRoute>) {
    let lines: Vec<&str> = yaml.lines().collect();
    let mut drop = HashSet::new();
    let mut insert_after: HashMap<usize, (usize, &SubscriptionFields)> = HashMap::new();
    let mut found = HashSet::new();

    for item in endpoint_items(&lines) {
        let (Some(route), Some(block)) = (item.route(), item.subscription) else {
            continue;
        };
        let Some(fields) = updates.get(&route) else {
            continue;
        };
        for idx in block.children.clone() {
            let stripped = lines[idx].trim_start();
            if indent_of(lines[idx]) == block.child_indent
                && fields
                    .iter()
                    .any(|(key, _)| key_value(stripped, key).is_some())
            {
                drop.insert(idx);
            }
        }
        insert_after.insert(block.last_content, (block.child_indent, fields));
        found.insert(route);
    }

    let mut out = String::with_capacity(yaml.len() + 512);
    for (idx, line) in lines.iter().enumerate() {
        if !drop.contains(&idx) {
            out.push_str(line);
            out.push('\n');
        }
        if let Some((indent, fields)) = insert_after.get(&idx) {
            for (key, value) in fields.iter() {
                out.push_str(&" ".repeat(*indent));
                out.push_str(key);
                out.push_str(": ");
                out.push_str(value);
                out.push('\n');
            }
        }
    }

    let missing = updates
        .keys()
        .filter(|route| !found.contains(*route))
        .cloned()
        .collect();
    (out, missing)
}

struct SubscriptionBlock {
    /// Child line indices (may include blanks and comments).
    children: std::ops::Range<usize>,
    child_indent: usize,
    /// Line after which new fields go: the last non-blank, non-comment child,
    /// or the `subscription:` line itself when the block is empty.
    last_content: usize,
}

#[derive(Default)]
struct EndpointItem {
    method: Option<HttpMethod>,
    path: Option<String>,
    subscription: Option<SubscriptionBlock>,
}

impl EndpointItem {
    fn route(&self) -> Option<PlanRoute> {
        Some(PlanRoute::new(self.method.as_ref()?, self.path.as_deref()?))
    }
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_content(line: &str) -> bool {
    let stripped = line.trim_start();
    !stripped.is_empty() && !stripped.starts_with('#')
}

/// `Some(value)` when `stripped` is `key: value`, with quotes and any
/// trailing comment removed.
fn key_value<'a>(stripped: &'a str, key: &str) -> Option<&'a str> {
    let rest = stripped.strip_prefix(key)?.strip_prefix(':')?;
    if !rest.is_empty() && !rest.starts_with(' ') {
        return None;
    }
    let rest = rest.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = rest.strip_prefix(quote) {
            return Some(inner.split(quote).next().unwrap_or(inner));
        }
    }
    Some(rest.split(" #").next().unwrap_or(rest).trim_end())
}

/// Split the top-level `endpoints:` sequence into items and read each item's
/// own `method`, `path` and `subscription` keys. Keys nested deeper (such as
/// `routing.auth.method`) are ignored.
fn endpoint_items(lines: &[&str]) -> Vec<EndpointItem> {
    let Some(start) = lines
        .iter()
        .position(|line| indent_of(line) == 0 && key_value(line, "endpoints").is_some())
    else {
        return Vec::new();
    };

    let mut items = Vec::new();
    let mut idx = start + 1;
    let Some(item_indent) = lines[idx.min(lines.len())..]
        .iter()
        .find(|line| is_content(line))
        .filter(|line| line.trim_start().starts_with('-'))
        .map(|line| indent_of(line))
    else {
        return items;
    };

    while idx < lines.len() {
        let line = lines[idx];
        if !is_content(line) {
            idx += 1;
            continue;
        }
        let indent = indent_of(line);
        let stripped = line.trim_start();
        if indent < item_indent || (indent == item_indent && !stripped.starts_with('-')) {
            break;
        }
        // `- key: value` — the item's keys align with the first key after `-`.
        let after_dash = &stripped[1..];
        let field_indent = indent + 1 + (after_dash.len() - after_dash.trim_start().len());
        let mut item = EndpointItem::default();
        let mut cursor = idx;
        let mut first = Some(after_dash.trim_start());
        loop {
            let key_line = match first.take() {
                Some(text) => Some(text),
                None if indent_of(lines[cursor]) == field_indent && is_content(lines[cursor]) => {
                    Some(lines[cursor].trim_start())
                }
                None => None,
            };
            if let Some(text) = key_line {
                if let Some(value) = key_value(text, "method") {
                    item.method = serde_yml::from_str(value).ok();
                } else if let Some(value) = key_value(text, "path") {
                    item.path = Some(value.to_string());
                } else if key_value(text, "subscription") == Some("") {
                    item.subscription = Some(subscription_block(lines, cursor, field_indent));
                }
            }
            cursor += 1;
            if cursor >= lines.len() {
                break;
            }
            let next = lines[cursor];
            if is_content(next) && indent_of(next) < field_indent {
                break;
            }
        }
        items.push(item);
        idx = cursor;
    }
    items
}

fn subscription_block(lines: &[&str], at: usize, key_indent: usize) -> SubscriptionBlock {
    let mut end = at + 1;
    let mut last_content = at;
    let mut child_indent = None;
    while end < lines.len() {
        let line = lines[end];
        if is_content(line) {
            if indent_of(line) <= key_indent {
                break;
            }
            child_indent.get_or_insert(indent_of(line));
            last_content = end;
        }
        end += 1;
    }
    SubscriptionBlock {
        children: at + 1..end,
        child_indent: child_indent.unwrap_or(key_indent + 2),
        last_content,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(method: HttpMethod, path: &str) -> PlanRoute {
        PlanRoute::new(&method, path)
    }

    fn plan_id(value: &str) -> SubscriptionFields {
        vec![("plan_id", value.to_string())]
    }

    #[test]
    fn same_path_routes_keep_their_own_fields() {
        let yaml = "\
endpoints:
  - method: GET
    path: v1/feed
    routing:
      auth:
        method: bearer
    subscription:
      period: 30d
      plan_id: OLD_GET
  - path: \"v1/feed\"
    subscription:
      period: 7d
    method: POST
";
        let updates = HashMap::from([
            (route(HttpMethod::Get, "v1/feed"), plan_id("GET_PLAN")),
            (route(HttpMethod::Post, "v1/feed"), plan_id("POST_PLAN")),
        ]);
        let (out, missing) = rewrite_subscription_fields(yaml, &updates);
        assert!(missing.is_empty(), "{missing:?}");
        assert_eq!(
            out,
            "\
endpoints:
  - method: GET
    path: v1/feed
    routing:
      auth:
        method: bearer
    subscription:
      period: 30d
      plan_id: GET_PLAN
  - path: \"v1/feed\"
    subscription:
      period: 7d
      plan_id: POST_PLAN
    method: POST
"
        );
    }

    #[test]
    fn unmatched_routes_are_reported() {
        let yaml = "endpoints:\n  - method: GET\n    path: v1/feed\n    subscription:\n      period: 30d\n";
        let updates = HashMap::from([(route(HttpMethod::Post, "v1/feed"), plan_id("X"))]);
        let (out, missing) = rewrite_subscription_fields(yaml, &updates);
        assert_eq!(out, yaml);
        assert_eq!(missing, vec![route(HttpMethod::Post, "v1/feed")]);
    }

    #[test]
    fn unindented_sequences_and_comments_survive() {
        let yaml = "endpoints:\n# lead\n- method: GET\n  path: v1/feed # trailing\n  subscription:\n    period: 30d\n\n    # tail\nrouting: {}\n";
        let updates = HashMap::from([(route(HttpMethod::Get, "v1/feed"), plan_id("P"))]);
        let (out, missing) = rewrite_subscription_fields(yaml, &updates);
        assert!(missing.is_empty());
        assert_eq!(
            out,
            "endpoints:\n# lead\n- method: GET\n  path: v1/feed # trailing\n  subscription:\n    period: 30d\n    plan_id: P\n\n    # tail\nrouting: {}\n"
        );
    }
}
