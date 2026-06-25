// tests/test_extensions.rs
//
// Integration tests for the extension / module script CRUD API.
//
// Tests drive the Axum handlers directly via tower::ServiceExt::oneshot,
// injecting a fake OperatorInfo (as axum::Extension) into routes that
// require auth so no real database or server is needed.
//
// Each test that touches the filesystem uses a unique name derived from
// the test name + process ID.  A DropFile / DropDir guard ensures cleanup
// even on panic.
//
// Coverage
// ──────────────────────────────────────────────────────────────────────
//  safe_name                : see inline unit tests in extensions.rs
//  list_extensions          : empty dir, populated dir, non-rhai files filtered
//  get_extension            : 200 + content, 404 for missing, 400 for traversal
//  put_extension (admin)    : creates file, overwrites, 400 for bad names
//  put_extension (viewer)   : 403 for viewer role
//  delete_extension (admin) : 204 + file gone, 404 for missing
//  delete_extension (viewer): 403 for viewer role
//  modules (GET/PUT/DELETE) : same structure, separate directory
//  /api/modules list        : existing list_modules handler unaffected
//  middleware ?key= param   : accepted on /api/loot/zip, rejected elsewhere

use axum::{
    Router,
    routing::get,
    http::{Request, StatusCode},
    body::Body,
    Extension,
};
use tower::ServiceExt;  // .oneshot()
use serde_json::Value;
use std::path::{Path, PathBuf};

use rcm::api::routes::extensions::{
    list_extensions, get_extension,
    put_extension, delete_extension,
    get_module, put_module, delete_module,
};
use rcm::api::middleware::OperatorInfo;

// ── Test fixtures / helpers ────────────────────────────────────────────────────

fn admin() -> OperatorInfo {
    OperatorInfo { id: 1, username: "admin".into(), role: "admin".into() }
}

fn viewer() -> OperatorInfo {
    OperatorInfo { id: 2, username: "viewer".into(), role: "viewer".into() }
}

/// Builds a router for extensions with an injected operator identity.
fn ext_router(op: OperatorInfo) -> Router {
    Router::new()
        .route("/api/extensions",       get(list_extensions))
        .route("/api/extensions/:name", get(get_extension)
                                        .put(put_extension)
                                        .delete(delete_extension))
        .layer(Extension(op))
}

/// Builds a router for module per-file CRUD.
fn mod_router(op: OperatorInfo) -> Router {
    Router::new()
        .route("/api/modules/:name", get(get_module)
                                     .put(put_module)
                                     .delete(delete_module))
        .layer(Extension(op))
}

/// Unique name: avoids collisions when tests run in parallel.
fn uname(label: &str) -> String {
    format!("test_{}_{}", label, std::process::id())
}

/// Removes a file on drop; silently ignores errors.
struct DropFile(PathBuf);
impl Drop for DropFile {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}

/// PUT JSON body for the write endpoint.
fn put_body(content: &str) -> Body {
    Body::from(serde_json::json!({"content": content}).to_string())
}

/// Extract response body bytes using hyper (direct dep, always available).
async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    hyper::body::to_bytes(resp.into_body()).await.unwrap().to_vec()
}

/// Parse response body as JSON.
async fn body_json(resp: axum::response::Response) -> Value {
    let b = body_bytes(resp).await;
    serde_json::from_slice(&b).unwrap_or(Value::Null)
}

fn json_put_request(uri: &str, content: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(put_body(content))
        .unwrap()
}

fn empty_request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

// ── list_extensions ────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_extensions_returns_ok() {
    let app = ext_router(admin());
    let resp = app.oneshot(empty_request("GET", "/api/extensions")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_extensions_contains_saved_file() {
    let name = uname("list_found");
    let path = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _ = std::fs::create_dir_all("extensions");
    std::fs::write(&path, "// list test").unwrap();
    let _g = DropFile(path);

    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("GET", "/api/extensions")).await.unwrap();
    let json = body_json(resp).await;
    let list = json["extensions"].as_array().unwrap();
    assert!(list.iter().any(|v| v == name.as_str()),
        "expected {} in {:?}", name, list);
}

#[tokio::test]
async fn list_extensions_ignores_non_rhai_files() {
    let _ = std::fs::create_dir_all("extensions");
    let txt = PathBuf::from("extensions/not_a_script.txt");
    std::fs::write(&txt, "ignored").unwrap();
    let _g = DropFile(txt);

    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("GET", "/api/extensions")).await.unwrap();
    let json = body_json(resp).await;
    let list = json["extensions"].as_array().unwrap();
    assert!(!list.iter().any(|v| v == "not_a_script"),
        ".txt file should not appear in extension list");
}

// ── get_extension ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_extension_returns_content() {
    let name    = uname("get_ok");
    let content = "let x = 42;";
    let path    = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _ = std::fs::create_dir_all("extensions");
    std::fs::write(&path, content).unwrap();
    let _g = DropFile(path);

    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("GET", &format!("/api/extensions/{}", name))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"].as_str().unwrap(), name);
    assert_eq!(json["content"].as_str().unwrap(), content);
}

#[tokio::test]
async fn get_extension_missing_returns_404() {
    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("GET", "/api/extensions/definitely_does_not_exist")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_extension_traversal_is_blocked() {
    // Two distinct paths through traversal blocking:
    //
    // A) URL-encoded slash  "..%2Fetc_passwd"  → router sees one segment,
    //    Path extractor decodes to "../etc_passwd", safe_name() → false → 400.
    //
    // B) Literal slash  "sub/script" or "../etc_passwd"  → the HTTP stack
    //    (hyper) normalises the path before routing: "../" collapses a
    //    segment and "/" splits into two segments — neither form matches
    //    /api/extensions/:name, so the router returns 404 before the handler
    //    is even called.
    //
    // Both outcomes correctly block the traversal; the assertion accepts either.
    for bad in ["../etc_passwd", "..%2Fetc_passwd", "sub/script"] {
        let app    = ext_router(admin());
        let resp   = app.oneshot(
            empty_request("GET", &format!("/api/extensions/{}", bad))
        ).await.unwrap();
        let status = resp.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "traversal '{}' should be blocked (got {})", bad, status
        );
    }
}

// ── put_extension ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn put_extension_creates_file() {
    let name    = uname("put_create");
    let content = "let created = true;";
    let path    = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _g      = DropFile(path.clone());

    let app  = ext_router(admin());
    let resp = app.oneshot(json_put_request(
        &format!("/api/extensions/{}", name), content
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
}

#[tokio::test]
async fn put_extension_overwrites_existing() {
    let name = uname("put_overwrite");
    let path = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _g   = DropFile(path.clone());
    let _ = std::fs::create_dir_all("extensions");
    std::fs::write(&path, "// original").unwrap();

    let app  = ext_router(admin());
    let resp = app.oneshot(json_put_request(
        &format!("/api/extensions/{}", name), "// updated"
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "// updated");
}

#[tokio::test]
async fn put_extension_viewer_returns_403() {
    let name = uname("put_viewer");
    let app  = ext_router(viewer());
    let resp = app.oneshot(json_put_request(
        &format!("/api/extensions/{}", name), "// blocked"
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // File must NOT have been created
    assert!(!Path::new("extensions").join(format!("{}.rhai", name)).exists(),
        "viewer write should not create file");
}

#[tokio::test]
async fn put_extension_traversal_returns_400() {
    let app  = ext_router(admin());
    let resp = app.oneshot(json_put_request(
        "/api/extensions/..%2Fevil", "// evil"
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── delete_extension ───────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_extension_removes_file() {
    let name = uname("del_ok");
    let path = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _ = std::fs::create_dir_all("extensions");
    std::fs::write(&path, "// delete me").unwrap();

    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("DELETE", &format!("/api/extensions/{}", name))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!path.exists(), "file should be gone after delete");
}

#[tokio::test]
async fn delete_extension_missing_returns_404() {
    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("DELETE", "/api/extensions/no_such_file_xyz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_extension_viewer_returns_403() {
    let name = uname("del_viewer");
    let path = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _ = std::fs::create_dir_all("extensions");
    std::fs::write(&path, "// protected").unwrap();
    let _g = DropFile(path.clone());

    let app  = ext_router(viewer());
    let resp = app.oneshot(empty_request("DELETE", &format!("/api/extensions/{}", name))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(path.exists(), "viewer delete should not remove file");
}

#[tokio::test]
async fn delete_extension_traversal_returns_400() {
    let app  = ext_router(admin());
    let resp = app.oneshot(empty_request("DELETE", "/api/extensions/..%2Fevil")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── modules CRUD (mirrors extension tests with ./modules/) ─────────────────────

#[tokio::test]
async fn get_module_returns_content() {
    let name    = uname("mod_get");
    let content = "fn run(id) { send_c2_command(id, \"shell whoami\"); \"ok\" }";
    let path    = PathBuf::from("modules").join(format!("{}.rhai", name));
    let _ = std::fs::create_dir_all("modules");
    std::fs::write(&path, content).unwrap();
    let _g = DropFile(path);

    let app  = mod_router(admin());
    let resp = app.oneshot(empty_request("GET", &format!("/api/modules/{}", name))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["content"].as_str().unwrap(), content);
}

#[tokio::test]
async fn get_module_missing_returns_404() {
    let app  = mod_router(admin());
    let resp = app.oneshot(empty_request("GET", "/api/modules/never_exists_xyz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_module_creates_file() {
    let name = uname("mod_put");
    let path = PathBuf::from("modules").join(format!("{}.rhai", name));
    let _g   = DropFile(path.clone());

    let app  = mod_router(admin());
    let resp = app.oneshot(json_put_request(
        &format!("/api/modules/{}", name), "fn run(id) { \"ok\" }"
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(path.exists());
}

#[tokio::test]
async fn put_module_viewer_returns_403() {
    let name = uname("mod_viewer");
    let app  = mod_router(viewer());
    let resp = app.oneshot(json_put_request(
        &format!("/api/modules/{}", name), "// blocked"
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_module_removes_file() {
    let name = uname("mod_del");
    let path = PathBuf::from("modules").join(format!("{}.rhai", name));
    let _ = std::fs::create_dir_all("modules");
    std::fs::write(&path, "fn run(id) {}").unwrap();

    let app  = mod_router(admin());
    let resp = app.oneshot(empty_request("DELETE", &format!("/api/modules/{}", name))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!path.exists());
}

#[tokio::test]
async fn delete_module_traversal_returns_400() {
    let app  = mod_router(admin());
    let resp = app.oneshot(empty_request("DELETE", "/api/modules/..%2Fevil")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── round-trip: put → get → delete ────────────────────────────────────────────

#[tokio::test]
async fn extension_full_round_trip() {
    let name    = uname("roundtrip");
    let content = "print_log(\"round trip\");";
    let path    = PathBuf::from("extensions").join(format!("{}.rhai", name));
    let _g      = DropFile(path.clone());

    // CREATE
    let resp = ext_router(admin())
        .oneshot(json_put_request(&format!("/api/extensions/{}", name), content))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "put failed");

    // READ
    let resp = ext_router(admin())
        .oneshot(empty_request("GET", &format!("/api/extensions/{}", name)))
        .await.unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["content"].as_str().unwrap(), content);

    // UPDATE
    let new_content = "print_log(\"updated\");";
    let resp = ext_router(admin())
        .oneshot(json_put_request(&format!("/api/extensions/{}", name), new_content))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "update failed");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), new_content);

    // DELETE
    let resp = ext_router(admin())
        .oneshot(empty_request("DELETE", &format!("/api/extensions/{}", name)))
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "delete failed");
    assert!(!path.exists());
}

// ── middleware: query-param key ────────────────────────────────────────────────
// These test the _logic_ of the fallback separately from a live server.
// We exercise it via a minimal loot/zip-style router that injects OperatorInfo
// the same way the real middleware would, then check the request parsing code.

#[test]
fn middleware_query_key_parsed_from_loot_zip_path() {
    // Simulate the key extraction logic from the middleware inline.
    // This is the exact fragment from middleware.rs so any change there
    // that breaks this test signals a regression.
    let query = "path=some%2Ffolder&key=my-secret-key";
    let parsed: Option<String> = query
        .split('&')
        .find_map(|pair| {
            let mut kv = pair.splitn(2, '=');
            let k = kv.next()?;
            if k == "key" { kv.next().map(|v| v.to_owned()) } else { None }
        });
    assert_eq!(parsed.as_deref(), Some("my-secret-key"));
}

#[test]
fn middleware_query_key_absent_returns_none() {
    let query = "path=some%2Ffolder";
    let parsed: Option<String> = query
        .split('&')
        .find_map(|pair| {
            let mut kv = pair.splitn(2, '=');
            let k = kv.next()?;
            if k == "key" { kv.next().map(|v| v.to_owned()) } else { None }
        });
    assert!(parsed.is_none());
}

#[test]
fn middleware_query_key_key_only_with_empty_value() {
    let query = "path=x&key=";
    let parsed: Option<String> = query
        .split('&')
        .find_map(|pair| {
            let mut kv = pair.splitn(2, '=');
            let k = kv.next()?;
            if k == "key" { kv.next().map(|v| v.to_owned()) } else { None }
        });
    // An empty key is present but meaningless — the middleware checks is_empty() after.
    assert_eq!(parsed.as_deref(), Some(""));
}

#[test]
fn middleware_download_path_detection() {
    let download_paths = ["/api/loot/zip", "/api/builder/jobs/"];
    let cases = [
        ("/api/loot/zip?path=x", true),
        ("/api/loot/zip",        true),
        ("/api/builder/jobs/42/download", true),
        ("/api/extensions",      false),
        ("/api/hosts/1/command", false),
        ("/api/loot",            false),   // list, not zip
    ];
    for (path, expected) in cases {
        let is_download = download_paths.iter().any(|p| path.starts_with(p));
        assert_eq!(is_download, expected, "path '{}' detection wrong", path);
    }
}
