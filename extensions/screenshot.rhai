// extensions/screenshot.rhai
print_log("Taking screenshot...");
let json_data = internal_screenshot();

// Static-musl builds ship a stub that returns an empty array, and on a
// Linux host without an X11 display the capture list is empty too. Surface
// that instead of handing the server an empty SCREENSHOT_DUMP.
if json_data == "[]" {
    return "Screenshot unavailable: musl stub build, or no display attached.";
}

return "SCREENSHOT_DUMP:" + json_data;
