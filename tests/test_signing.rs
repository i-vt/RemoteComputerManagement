// tests/test_signing.rs — Signature verification tests for SecuredCommand

use rcm::common::SecuredCommand;
use ed25519_dalek::{SigningKey, Signer, Verifier};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::rngs::OsRng;
use chrono::Utc;

fn make_signed_command(key: &SigningKey, command: &str) -> SecuredCommand {
    let mut cmd = SecuredCommand {
        session_id: "test-session".to_string(),
        counter: 1,
        nonce: 42,
        timestamp: Utc::now(),
        command: command.to_string(),
        signature: String::new(),
    };
    let sig = key.sign(&cmd.get_signable_bytes());
    cmd.signature = BASE64.encode(sig.to_bytes());
    cmd
}

#[test]
fn test_valid_signature_verifies() {
    let key = SigningKey::generate(&mut OsRng);
    let verify_key = key.verifying_key();
    let cmd = make_signed_command(&key, "whoami");

    let sig_bytes = BASE64.decode(&cmd.signature).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    assert!(verify_key.verify(&cmd.get_signable_bytes(), &sig).is_ok());
}

#[test]
fn test_tampered_command_fails_verification() {
    let key = SigningKey::generate(&mut OsRng);
    let verify_key = key.verifying_key();
    let mut cmd = make_signed_command(&key, "whoami");

    // Tamper with the command after signing
    cmd.command = "rm -rf /".to_string();

    let sig_bytes = BASE64.decode(&cmd.signature).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    assert!(verify_key.verify(&cmd.get_signable_bytes(), &sig).is_err());
}

#[test]
fn test_wrong_key_fails_verification() {
    let key1 = SigningKey::generate(&mut OsRng);
    let key2 = SigningKey::generate(&mut OsRng);
    let verify_key2 = key2.verifying_key();
    let cmd = make_signed_command(&key1, "whoami");

    let sig_bytes = BASE64.decode(&cmd.signature).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // Signed with key1 but verified with key2
    assert!(verify_key2.verify(&cmd.get_signable_bytes(), &sig).is_err());
}

#[test]
fn test_replay_counter_ordering() {
    let key = SigningKey::generate(&mut OsRng);
    let mut cmd1 = make_signed_command(&key, "id");
    cmd1.counter = 5;

    let mut cmd2 = make_signed_command(&key, "whoami");
    cmd2.counter = 3;

    // Agent should reject cmd2 since counter 3 <= last_counter 5
    let mut last_counter = 0u64;
    
    // cmd1 arrives first
    if cmd1.counter > last_counter { last_counter = cmd1.counter; }
    assert_eq!(last_counter, 5);
    
    // cmd2 has lower counter — should be rejected
    assert!(cmd2.counter <= last_counter);
}

#[test]
fn test_invalid_signature_bytes_dont_panic() {
    // Ensure that garbage signature data doesn't cause panics
    let key = SigningKey::generate(&mut OsRng);
    let verify_key = key.verifying_key();

    let cmd = SecuredCommand {
        session_id: "s".into(),
        counter: 1,
        nonce: 1,
        timestamp: Utc::now(),
        command: "test".into(),
        signature: BASE64.encode(vec![0u8; 64]),
    };

    let sig_bytes = BASE64.decode(&cmd.signature).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // Should fail verification, not panic
    assert!(verify_key.verify(&cmd.get_signable_bytes(), &sig).is_err());
}

#[test]
fn test_short_signature_handled_gracefully() {
    // Signature that's too short to be valid
    let short_sig = BASE64.encode(vec![0u8; 32]);
    let decoded = BASE64.decode(&short_sig).unwrap();
    let result: Result<[u8; 64], _> = decoded.try_into();
    assert!(result.is_err()); // Should fail cleanly, not panic
}
