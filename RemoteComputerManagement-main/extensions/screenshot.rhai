// extensions/screenshot.rhai
print_log("Taking screenshot...");
let json_data = internal_screenshot();
return "SCREENSHOT_DUMP:" + json_data;
