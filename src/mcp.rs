//! Minimal MCP (Model Context Protocol) JSON-RPC message builders.
//!
//! Just enough to drive a stdio MCP server through a flight plan: initialize,
//! enumerate tools, and invoke one benign tool. gurgl is not a full MCP client;
//! it only needs to make the server *do representative work* so its real egress
//! is exercised.

use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// `initialize` — the required handshake before any other call.
pub fn initialize(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "gurgl", "version": env!("CARGO_PKG_VERSION") }
        }
    })
}

/// The `notifications/initialized` notification sent after `initialize` returns.
pub fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

/// `tools/list` — enumerate available tools.
pub fn tools_list(id: u64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" })
}

/// `tools/call` — invoke a tool by name with arguments.
pub fn tools_call(id: u64, name: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

/// Serialize a JSON-RPC message as a single line (newline-delimited framing,
/// the common stdio convention for MCP servers).
pub fn to_line(value: &Value) -> String {
    let mut s = value.to_string();
    s.push('\n');
    s
}
