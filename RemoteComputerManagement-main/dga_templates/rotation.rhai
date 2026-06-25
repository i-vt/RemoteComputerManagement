// dga_templates/rotation.rhai
// Returns a domain based on the failure count
fn next_domain(failure_count, timestamp) {
    let domains = [
        "127.0.0.1",
        "backup.c2.local",
        "fallback.example.com",
        "192.168.56.102"
    ];

    let index = failure_count % domains.len();
    return domains[index];
}
