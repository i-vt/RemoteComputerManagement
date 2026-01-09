print_log("Starting Environment Audit...");

let sensitive_vars = [
    "AWS_ACCESS_KEY_ID", 
    "AWS_SECRET_ACCESS_KEY", 
    "AZURE_CLIENT_ID", 
    "GOOGLE_APPLICATION_CREDENTIALS",
    "KUBECONFIG", 
    "DOCKER_HOST", 
    "GitLab_Token"
];

let sys_vars = ["COMPUTERNAME", "USERNAME", "USERPROFILE", "HOME", "PATH"];
let output = "=== ENV AUDIT RESULTS ===\n";

// 1. Check System Context
output = output + "[System Context]\n";
for var in sys_vars {
    let val = internal_env(var);
    if val != "Not Found" {
        output = output + "  " + var + ": " + val + "\n";
    }
}

// 2. Hunt for Secrets
output = output + "\n[Cloud & Secrets]\n";
let found_secrets = false;

for var in sensitive_vars {
    let val = internal_env(var);
    if val != "Not Found" {
        output = output + "  [!] FOUND " + var + ": " + val + "\n";
        found_secrets = true;
    }
}

if found_secrets == false {
    output = output + "  No cloud credentials found in env.\n";
}

return output;
