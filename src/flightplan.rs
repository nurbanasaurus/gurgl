//! Flight plans: the fixed, versioned battery of actions gurgl drives against a
//! server so its egress is exercised reproducibly.
//!
//! The plan is committed to the repo on purpose. An observation only means
//! anything relative to the exact steps that produced it, so the method travels
//! with the data.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightPlan {
    pub name: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        }
        format!("{}-{:016x}", self.name, acc)
    }
}
