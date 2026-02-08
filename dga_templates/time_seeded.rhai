// dga_templates/time_seeded.rhai
fn next_domain(failure_count, timestamp) {
    // timestamp is passed as Unix Seconds
    // Change domain every 3600 seconds (1 hour)
    let time_slot = timestamp / 3600; 
    let seed = "my_secret_seed_" + time_slot;
    
    // Use internal hashing (would need to expose hash fn or implement simple one)
    // For simplicity, we just append to a base
    return "update-" + time_slot + ".example.com";
}
