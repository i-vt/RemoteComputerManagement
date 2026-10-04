// Recovery for crypt_all_linux: recursively decrypt the filesystem.
// Pass the key printed by the crypt module run as the first argument.
// An optional second argument overrides the target path (default /).
fn run(session_id, args) {
    if args.len < 1 {
        return "Usage: decrypt_all_linux <hex_key> [path] - the key is printed by the crypt module run";
    }
    let key = args[0];
    let path = if args.len > 1 { args[1] } else { "/" };
    print("Decrypting " + path + " for session " + session_id);
    let res = send_c2_extension(session_id, "recursive_unlock", [path, key]);
    return "Deployed: " + res;
}
