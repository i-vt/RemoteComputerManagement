// extensions/grab_screen.rhai
print_log("Taking on-demand screenshot...");

// Get JSON array of all screens
let json_data = internal_screenshot();

// Return with the special tag for server extraction
return "SCREENSHOT_DUMP:" + json_data;
