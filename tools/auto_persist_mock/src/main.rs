// Mock harness: runs extensions/auto_persist.rhai against a simulated Windows
// environment on Linux. Validates the playbook logic end-to-end.
use rhai::{Dynamic, Engine, Scope};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

const STABLE: &str = r"C:\Users\victim\AppData\Roaming\Microsoft\SystemUpdateHelper.exe";
const STARTUP_DIR: &str = r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";
const RUN_HKCU: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemUpdateHelper";
const RUN_HKLM: &str = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SystemUpdateHelper";
const IFEO_KEY: &str = r"HKLM\IFEO\utilman.exe\Debugger";

#[derive(Clone, Default)]
struct MockState {
    registry: Arc<Mutex<HashSet<String>>>,
    tasks: Arc<Mutex<HashSet<String>>>,
    files: Arc<Mutex<HashSet<String>>>,
    wmi: Arc<Mutex<HashSet<String>>>,
    log: Arc<Mutex<Vec<String>>>,
    elevated: bool,
    fail_methods: HashSet<String>,
}

impl MockState {
    fn exec_cmd(&self, cmd: &str) -> String {
        self.log.lock().unwrap().push(cmd.to_string());
        let fail = |m: &str| self.fail_methods.contains(m);

        if cmd.contains("IsInRole") {
            return if self.elevated { "True".into() } else { "False".into() };
        }
        if cmd.contains("GetFolderPath('Startup')") {
            return STARTUP_DIR.to_string();
        }
        if cmd.contains("CreateShortcut") {
            if !fail("startup_folder") {
                let p = cmd.split("CreateShortcut('").nth(1).unwrap_or("").split('\'').next().unwrap_or("");
                self.files.lock().unwrap().insert(p.to_string());
            }
            return String::new();
        }
        if cmd.contains("Test-Path") {
            let p = cmd.split("-LiteralPath '").nth(1).unwrap_or("").split('\'').next().unwrap_or("");
            let exists = self.files.lock().unwrap().contains(p);
            if cmd.contains("{ 'OK' }") {   // stable_drop verification form
                return if exists { "OK".into() } else { String::new() };
            }
            return if exists { "EXISTS".into() } else { String::new() };
        }
        if cmd.contains("Copy-Item") || cmd.contains("New-Item") {
            let p = cmd.split("-Destination '").nth(1).unwrap_or("").split('\'').next().unwrap_or("");
            if !p.is_empty() { self.files.lock().unwrap().insert(p.to_string()); }
            return "OK".into();
        }
        if cmd.contains("reg add") {
            let hive = if cmd.contains("HKLM") { "HKLM" } else { "HKCU" };
            let method = if hive == "HKLM" { "registry_run_hklm" } else { "registry_run_hkcu" };
            if cmd.contains(r"CurrentVersion\Run") {
                if !fail(method) {
                    let key = if hive == "HKLM" { RUN_HKLM } else { RUN_HKCU };
                    self.registry.lock().unwrap().insert(key.to_string());
                }
                return "The operation completed successfully.".into();
            }
            if cmd.contains("Image File Execution Options") {
                if !fail("ifeo_debugger") {
                    self.registry.lock().unwrap().insert(IFEO_KEY.to_string());
                }
                return "The operation completed successfully.".into();
            }
            return String::new();
        }
        if cmd.contains("reg query") {
            if cmd.contains(r"CurrentVersion\Run") {
                let key = if cmd.contains("HKLM") { RUN_HKLM } else { RUN_HKCU };
                if self.registry.lock().unwrap().contains(key) {
                    return format!("    SystemUpdateHelper    REG_SZ    {}", STABLE);
                }
                return String::new();
            }
            if cmd.contains("Image File Execution Options") && cmd.contains("Debugger") {
                if self.registry.lock().unwrap().contains(IFEO_KEY) {
                    return format!("    Debugger    REG_SZ    {}", STABLE);
                }
                return String::new();
            }
            return String::new();
        }
        if cmd.contains("schtasks /create") {
            if !fail("scheduled_task") { self.tasks.lock().unwrap().insert("SystemUpdateHelper".to_string()); }
            return "SUCCESS: The scheduled task has been created.".into();
        }
        if cmd.contains("schtasks /query") {
            return if self.tasks.lock().unwrap().contains("SystemUpdateHelper") {
                "\"SystemUpdateHelper\",\"Ready\"".into()
            } else { String::new() };
        }
        if cmd.contains("sc.exe create") {
            if !fail("windows_service") { self.files.lock().unwrap().insert("svc:SystemUpdateHelper".into()); }
            return "[SC] CreateService SUCCESS".into();
        }
        if cmd.contains("sc.exe query") {
            return if self.files.lock().unwrap().contains("svc:SystemUpdateHelper") {
                "SERVICE_NAME: SystemUpdateHelper\n        STATE              : 1  STOPPED".into()
            } else { String::new() };
        }
        if cmd.contains("Set-WmiInstance") {
            if !fail("wmi_event_subscription") { self.wmi.lock().unwrap().insert("SystemUpdateHelperF".into()); }
            return String::new();
        }
        if cmd.contains("Get-WmiObject") {
            return if self.wmi.lock().unwrap().contains("SystemUpdateHelperF") { "SystemUpdateHelperF".into() } else { String::new() };
        }
        String::new()
    }
}

fn method_order(cmds: &[String]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for c in cmds {
        let m = if c.contains(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run") && c.contains("reg add") { Some("registry_run_hkcu") }
            else if c.contains("schtasks /create") { Some("scheduled_task") }
            else if c.contains("CreateShortcut") { Some("startup_folder") }
            else if c.contains(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run") && c.contains("reg add") { Some("registry_run_hklm") }
            else if c.contains("sc.exe create") { Some("windows_service") }
            else if c.contains("__EventFilter") && c.contains("Set-WmiInstance") { Some("wmi_event_subscription") }
            else if c.contains("Image File Execution Options") && c.contains("Debugger") && c.contains("reg add") { Some("ifeo_debugger") }
            else { None };
        if let Some(m) = m { out.push(m); }
    }
    out
}

fn run(script: &str, st: &MockState) -> String {
    let mut engine = Engine::new();
    let mut scope = Scope::new();
    scope.push("args", Vec::<Dynamic>::new());

    engine.register_fn("internal_env", |name: &str| -> String {
        match name {
            "SystemRoot" => r"C:\Windows".to_string(),
            "APPDATA" => r"C:\Users\victim\AppData\Roaming".to_string(),
            "HOME" => String::new(),
            "USERPROFILE" => r"C:\Users\victim".to_string(),
            _ => String::new(),
        }
    });
    engine.register_fn("internal_self_path", || r"C:\Users\victim\agent.exe".to_string());
    engine.register_fn("internal_read", |_p: &str| "Error: not found".to_string());
    let st_w = st.clone();
    engine.register_fn("internal_write", move |p: &str, _c: &str| { st_w.files.lock().unwrap().insert(p.to_string()); "Success".to_string() });
    engine.register_fn("print_log", |_s: &str| {});

    let s1 = st.clone();
    engine.register_fn("exec_os_timeout", move |cmd: &str, _secs: i64| -> String { s1.exec_cmd(cmd) });
    let s2 = st.clone();
    engine.register_fn("exec_os", move |cmd: &str| -> String { s2.exec_cmd(cmd) });

    engine.eval_with_scope::<String>(&mut scope, script).unwrap_or_else(|e| {
        eprintln!("SCRIPT ERROR: {}", e);
        "{\"result\":\"error\",\"detail\":\"script error\"}".to_string()
    })
}

fn main() {
    let script = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut failures = 0;

    let scenarios: Vec<(&str, bool, Vec<&str>, &str, &str)> = vec![
        ("user_ok", false, vec![], "success", "registry_run_hkcu"),
        ("user_m1_m2_fail_startup_wins", false, vec!["registry_run_hkcu", "scheduled_task"], "success", "startup_folder"),
        ("elevated_fallback_hklm", true, vec!["registry_run_hkcu", "scheduled_task", "startup_folder"], "success", "registry_run_hklm"),
        ("elevated_service", true, vec!["registry_run_hkcu", "scheduled_task", "startup_folder", "registry_run_hklm"], "success", "windows_service"),
        ("elevated_wmi", true, vec!["registry_run_hkcu", "scheduled_task", "startup_folder", "registry_run_hklm", "windows_service"], "success", "wmi_event_subscription"),
        ("elevated_ifeo", true, vec!["registry_run_hkcu", "scheduled_task", "startup_folder", "registry_run_hklm", "windows_service", "wmi_event_subscription"], "success", "ifeo_debugger"),
        ("user_all_fail", false, vec!["registry_run_hkcu", "scheduled_task", "startup_folder"], "all_failed", ""),
        ("user_elevated_skip_note", false, vec!["registry_run_hkcu", "scheduled_task"], "success", "startup_folder"),
    ];

    for (name, elevated, fails, want_result, want_method) in &scenarios {
        let mut st = MockState { elevated: *elevated, ..Default::default() };
        st.fail_methods = fails.iter().map(|s| s.to_string()).collect();

        let out = run(&script, &st);
        let j: Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("[{}] output is not valid JSON: {}\nRAW: {}", name, e, out));

        let got_result = j["result"].as_str().unwrap_or("?");
        let got_method = j["method"].as_str().unwrap_or("");
        let skipped = j["skipped_elevated"].as_str().unwrap_or("");

        let mut ok = got_result == *want_result && got_method == *want_method;
        if !ok {
            println!("FAIL [{}]: result={} method={} (want {} / {})", name, got_result, got_method, want_result, want_method);
        }

        let cmds = st.log.lock().unwrap().clone();
        let order = method_order(&cmds);
        let expect_order: Vec<&str> = if *elevated {
            vec!["registry_run_hkcu", "scheduled_task", "startup_folder", "registry_run_hklm", "windows_service", "wmi_event_subscription", "ifeo_debugger"]
        } else {
            vec!["registry_run_hkcu", "scheduled_task", "startup_folder"]
        };
        let reached: Vec<&str> = order.into_iter().filter(|m| expect_order.contains(m)).collect();
        // The playbook stops at the first SUCCESS: expected attempts are the
        // prefix of expect_order up to and including the successful method,
        // or the full prefix if everything failed.
        let expected_attempted: Vec<&str> = match expect_order.iter().position(|m| *m == *want_method) {
            Some(idx) => expect_order[..=idx].to_vec(),
            None => expect_order.clone(),
        };
        if reached != expected_attempted {
            println!("FAIL [{}]: method order {:?} (expected {:?})", name, reached, expected_attempted);
            ok = false;
        }

        if *name == "user_all_fail" && !skipped.contains("wmi_event_subscription") {
            println!("FAIL [{}]: skipped_elevated missing WMI entry: '{}'", name, skipped);
            ok = false;
        }
        if *name == "user_elevated_skip_note" && !skipped.contains("windows_service") {
            println!("FAIL [{}]: skipped_elevated missing service entry: '{}'", name, skipped);
            ok = false;
        }

        if ok { println!("PASS [{}]: result={} method={}", name, got_result, got_method); }
        else { failures += 1; }
    }

    let mut st = MockState::default();
    st.registry.lock().unwrap().insert(RUN_HKCU.to_string());
    let out = run(&script, &st);
    let j: Value = serde_json::from_str(&out).unwrap();
    if j["result"].as_str() == Some("already_persisted") {
        println!("PASS [already_persisted]");
    } else {
        println!("FAIL [already_persisted]: result={}", j["result"]);
        failures += 1;
    }

    if serde_json::from_str::<Value>(&run(&script, &MockState::default()))
        .unwrap().get("skipped_elevated").is_none() {
        println!("FAIL [json]: skipped_elevated field missing");
        failures += 1;
    } else {
        println!("PASS [json field present]");
    }

    if failures == 0 { println!("\nALL SCENARIOS PASSED"); }
    else { println!("\n{} FAILURES", failures); std::process::exit(1); }
}
