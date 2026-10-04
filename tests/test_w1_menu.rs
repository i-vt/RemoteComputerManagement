// tests/test_w1_menu.rs - Unit tests for the menu's pure command-string builders.
//
// Covers the upload wire format expected by the agent's handle_file_write:
// file:write|base_dir|rel_path|b64_data (agent splits with splitn(4, '|')),
// and the proxy:start wire format parsed by the agent's handle_proxy_start:
// "proxy:start <port> <tunnel_token>" (agent splits on whitespace).

use rcm::menu::handlers::build_upload_command;
use rcm::menu::proxy::build_proxy_start_command;

#[test]
fn upload_command_uses_four_field_wire_format() {
    let cmd = build_upload_command("loot/out.txt", "QUJD").unwrap();
    let fields: Vec<&str> = cmd.splitn(4, '|').collect();
    assert_eq!(fields.len(), 4, "agent requires exactly 4 pipe-separated fields");
    assert_eq!(fields[0], "file:write");
    assert_eq!(fields[1], "loot");
    assert_eq!(fields[2], "out.txt");
    assert_eq!(fields[3], "QUJD");
}

#[test]
fn upload_command_single_component_uses_dot_base() {
    // base/rel recombines to the typed path under the agent's working dir
    let cmd = build_upload_command("out.txt", "QQ==").unwrap();
    assert_eq!(cmd, "file:write|.|out.txt|QQ==");
}

#[test]
fn upload_command_preserves_nested_relative_path() {
    let cmd = build_upload_command("a/b/c.bin", "AA==").unwrap();
    assert_eq!(cmd, "file:write|a|b/c.bin|AA==");
}

#[test]
fn upload_command_b64_payload_survives_split() {
    // Base64 never contains '|', but '+' '/' and '=' must pass through intact.
    let cmd = build_upload_command("f", "a+b/c==").unwrap();
    let fields: Vec<&str> = cmd.splitn(4, '|').collect();
    assert_eq!(fields[3], "a+b/c==");
}

#[test]
fn upload_command_rejects_absolute_paths() {
    // write_file_simple on the agent refuses these; the builder must fail locally.
    assert!(build_upload_command("/etc/passwd", "QQ==").is_err());
    assert!(build_upload_command("\\\\share\\x", "QQ==").is_err());
    assert!(build_upload_command("C:\\temp\\x", "QQ==").is_err());
}

#[test]
fn upload_command_rejects_parent_traversal() {
    assert!(build_upload_command("../escape", "QQ==").is_err());
    assert!(build_upload_command("a/../b", "QQ==").is_err());
    assert!(build_upload_command("a\\..\\b", "QQ==").is_err());
}

#[test]
fn upload_command_rejects_empty_and_directory_paths() {
    assert!(build_upload_command("", "QQ==").is_err());
    assert!(build_upload_command("   ", "QQ==").is_err());
    assert!(build_upload_command("dir/", "QQ==").is_err());
    assert!(build_upload_command("dir\\", "QQ==").is_err());
}

#[test]
fn proxy_start_command_includes_port_and_token() {
    let cmd = build_proxy_start_command(4444, "0123456789abcdef0123456789abcdef");
    assert_eq!(cmd, "proxy:start 4444 0123456789abcdef0123456789abcdef");
}

#[test]
fn proxy_start_command_parses_as_agent_expects() {
    // Agent side: parts = cmd.split_whitespace(); parts[0] = "proxy:start",
    // parts[1] = port, parts.get(2) = optional token.
    let cmd = build_proxy_start_command(31337, "deadbeef");
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    assert_eq!(parts.len(), 3, "agent expects proxy:start <port> <token>");
    assert_eq!(parts[0], "proxy:start");
    assert_eq!(parts[1].parse::<u16>().unwrap(), 31337);
    assert_eq!(parts[2], "deadbeef");
}

#[test]
fn proxy_start_command_token_has_no_whitespace_or_pipes() {
    // A token containing spaces or '|' would corrupt the wire formats of
    // proxy:start (whitespace-split) and any pipe-delimited channel it rides
    // on; new_tunnel_token emits lowercase hex, and the builder must pass it
    // through verbatim without introducing separators.
    let token = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let cmd = build_proxy_start_command(1, token);
    assert!(!cmd.contains('|'));
    assert_eq!(cmd.matches(' ').count(), 2);
    assert!(cmd.ends_with(token));
}
