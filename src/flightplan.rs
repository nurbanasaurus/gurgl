//! Flight plans: the fixed, versioned battery of actions gurgl drives against a
//! server so its egress is exercised reproducibly.
//!
//! The plan is committed to the repo on purpose. An observation only means
//! anything relative to the exact steps that produced it, so the method travels
//! with the data.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// No `Eq`: `Step::args` holds a `toml::Value`, which can contain a float and so
// is `PartialEq` but not `Eq`. `PartialEq` is all we use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlightPlan {
    pub name: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    /// Lifecycle label recorded with any host seen during this step.
    pub phase: String,
    /// One of: "initialize", "tools/list", "tools/call", "sleep".
    pub action: String,
    /// For "tools/call": the tool name. If omitted, gurgl picks the first
    /// read-only-looking tool discovered by "tools/list".
    #[serde(default)]
    pub tool: Option<String>,
    /// For "sleep": duration in seconds.
    #[serde(default)]
    pub seconds: Option<u64>,
    /// For "tools/call": arguments passed to the tool, as a TOML table. This lets
    /// a plan exercise a real tool with real input (e.g. a URL to fetch) instead
    /// of an empty `{}`, so egress that only happens on a real call is captured.
    /// Defaults to `{}`.
    #[serde(default)]
    pub args: Option<toml::Value>,
}

impl Step {
    /// The tool-call arguments as JSON (`{}` when none are set).
    pub fn tool_args(&self) -> serde_json::Value {
        self.args
            .as_ref()
            .map(toml_to_json)
            .unwrap_or_else(|| serde_json::json!({}))
    }
}

/// Convert a parsed TOML value into the JSON gurgl sends over MCP.
fn toml_to_json(v: &toml::Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        toml::Value::String(s) => J::String(s.clone()),
        toml::Value::Integer(i) => J::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(J::Number)
            .unwrap_or(J::Null),
        toml::Value::Boolean(b) => J::Bool(*b),
        toml::Value::Datetime(d) => J::String(d.to_string()),
        toml::Value::Array(a) => J::Array(a.iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => J::Object(
            t.iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect(),
        ),
    }
}

impl FlightPlan {
    pub fn load(path: &Path) -> Result<FlightPlan> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading flight plan {}", path.display()))?;
        let plan: FlightPlan = toml::from_str(&text)
            .with_context(|| format!("parsing flight plan {}", path.display()))?;
        Ok(plan)
    }

    /// A stable hash-ish identifier for binding observations to the method.
    /// (Not cryptographic; just a fingerprint of the ordered steps.)
    pub fn fingerprint(&self) -> String {
        let mut acc: u64 = 1469598103934665603; // FNV-1a offset basis
        let mut mix = |s: &str| {
            for b in s.bytes() {
                acc ^= b as u64;
                acc = acc.wrapping_mul(1099511628211);
            }
        };
        mix(&self.name);
        for step in &self.steps {
            mix(&step.phase);
            mix(&step.action);
            if let Some(t) = &step.tool {
                mix(t);
            }
            // Different tool args exercise the server differently, so they are
            // part of the method the observation is bound to.
            if step.args.is_some() {
                if let Ok(s) = serde_json::to_string(&step.tool_args()) {
                    mix(&s);
                }
            }
        }
        format!("{}-{:016x}", self.name, acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_args_default_empty_and_parsed_table() {
        let plan: FlightPlan = toml::from_str(
            r#"
name = "t"
[[steps]]
phase = "startup"
action = "initialize"

[[steps]]
phase = "tool-call"
action = "tools/call"
tool = "fetch"
args = { url = "https://example.com", limit = 3 }
"#,
        )
        .unwrap();

        assert_eq!(plan.steps[0].tool_args(), serde_json::json!({}));
        assert_eq!(
            plan.steps[1].tool_args(),
            serde_json::json!({ "url": "https://example.com", "limit": 3 })
        );
        // args are part of the fingerprint.
        let mut bare = plan.clone();
        bare.steps[1].args = None;
        assert_ne!(plan.fingerprint(), bare.fingerprint());
    }
}
