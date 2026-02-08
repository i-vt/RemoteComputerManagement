// Usage: extension load clipboard_poison "You have been hacked!"
if args.len() == 0 { return "Usage: <text>"; }

let target_text = args[0];
print_log("Poisoning clipboard with: " + target_text);

let res = internal_clipboard_set(target_text);
return "Poison Result: " + res;
