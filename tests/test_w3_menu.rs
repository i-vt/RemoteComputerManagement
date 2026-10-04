// tests/test_w3_menu.rs - Unit tests for the unified proxy registry helpers.
//
// The menu and the REST API share one SharedProxies map . These tests
// pin the menu-side registry contract: atomic conflict-checked registration,
// handle removal for teardown, and stable listing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

use rcm::api::SharedProxies;
use rcm::api::state::ProxyHandle;
use rcm::menu::proxy::{try_register_proxy, take_proxy_handle, proxy_entries};

fn fresh_registry() -> SharedProxies {
    Arc::new(Mutex::new(HashMap::new()))
}

fn handle(session_id: u32, tunnel_port: u16, socks_port: u16) -> (ProxyHandle, oneshot::Receiver<()>) {
    let (stop_tx, stop_rx) = oneshot::channel();
    (ProxyHandle { session_id, tunnel_port, socks_port, stop_tx }, stop_rx)
}

#[test]
fn register_inserts_handle_and_lists_ports() {
    let proxies = fresh_registry();
    let (h, _rx) = handle(7, 40001, 40002);
    assert!(try_register_proxy(&proxies, h));
    assert_eq!(proxy_entries(&proxies), vec![(7, 40001, 40002)]);
}

#[test]
fn duplicate_registration_is_rejected_without_replacing() {
    let proxies = fresh_registry();
    let (h1, _rx1) = handle(7, 40001, 40002);
    let (h2, _rx2) = handle(7, 50001, 50002);
    assert!(try_register_proxy(&proxies, h1));
 // A start from the other side for the same session must lose honestly.
    assert!(!try_register_proxy(&proxies, h2));
 // The original handle keeps its slot and ports.
    assert_eq!(proxy_entries(&proxies), vec![(7, 40001, 40002)]);
}

#[test]
fn different_sessions_register_side_by_side() {
    let proxies = fresh_registry();
    let (h1, _rx1) = handle(2, 41001, 41002);
    let (h2, _rx2) = handle(1, 42001, 42002);
    assert!(try_register_proxy(&proxies, h1));
    assert!(try_register_proxy(&proxies, h2));
 // Listing is sorted by session id for stable display.
    assert_eq!(proxy_entries(&proxies), vec![(1, 42001, 42002), (2, 41001, 41002)]);
}

#[test]
fn take_removes_handle_for_teardown() {
    let proxies = fresh_registry();
    let (h, _rx) = handle(3, 43001, 43002);
    assert!(try_register_proxy(&proxies, h));
    let taken = take_proxy_handle(&proxies, 3).expect("handle must be present");
    assert_eq!(taken.session_id, 3);
    assert_eq!(taken.tunnel_port, 43001);
    assert!(take_proxy_handle(&proxies, 3).is_none());
    assert!(proxy_entries(&proxies).is_empty());
}

#[test]
fn taken_handle_stop_signal_reaches_runtime() {
    let proxies = fresh_registry();
    let (h, mut stop_rx) = handle(4, 44001, 44002);
    assert!(try_register_proxy(&proxies, h));
    let taken = take_proxy_handle(&proxies, 4).expect("handle must be present");
 // The stop path used by both menu and API: signal the runtime thread.
    taken.stop_tx.send(()).expect("receiver must still be alive");
    assert!(stop_rx.try_recv().is_ok());
}

#[test]
fn slot_is_reusable_after_teardown() {
    let proxies = fresh_registry();
    let (h1, _rx1) = handle(5, 45001, 45002);
    assert!(try_register_proxy(&proxies, h1));
    let _ = take_proxy_handle(&proxies, 5);
 // After a stop from either side, a new start must not wedge on a stale entry.
    let (h2, _rx2) = handle(5, 46001, 46002);
    assert!(try_register_proxy(&proxies, h2));
    assert_eq!(proxy_entries(&proxies), vec![(5, 46001, 46002)]);
}
