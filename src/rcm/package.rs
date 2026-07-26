// ./src/rcm/package.rs
// PackageManager: one RCM package per target (Section 3). ALL package
// writes are serialized through a single Mutex (`write_lock`), which
// satisfies the Section 6 locking discipline in-process: with only one
// writer at a time there is no intra-process lock-ordering hazard, and the
// atomic-write + create-exclusive primitives (REQ-6.3 / REQ-3.4.5) protect
// against concurrent foreign tools.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::Utc;
use md5::{Digest, Md5};
use sha2::Sha256;

use super::{counters, custody, fingerprint, logs, manifest, paths, sidecar, xml};
use crate::config::config;

/// Error type for all RCM operations.
#[derive(Debug)]
pub struct RcmError(pub String);

impl std::fmt::Display for RcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rcm: {}", self.0)
    }
}

impl std::error::Error for RcmError {}

impl From<std::io::Error> for RcmError {
    fn from(e: std::io::Error) -> Self {
        RcmError(e.to_string())
    }
}

impl From<String> for RcmError {
    fn from(s: String) -> Self {
        RcmError(s)
    }
}

impl From<&str> for RcmError {
    fn from(s: &str) -> Self {
        RcmError(s.to_string())
    }
}

/// Optional agent-supplied metadata for a collected file (Section 8.2).
#[derive(Default, Clone)]
pub struct CollectedMeta {
    pub modified: Option<String>, // canonical ts
    pub accessed: Option<String>,
    pub created: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

/// Section 11 (Table 6) screenshot metadata.
pub struct ScreenshotMeta {
    pub captured_at: chrono::DateTime<Utc>,
    pub toolspecific: String, // free-form context, e.g. "monitor0" (sanitized)
    pub ext: String,          // "png" | "jpg" | "bmp"
    pub originalsize: Option<String>, // "WxH"
    pub isfullscreen: Option<bool>,
    pub isminimized: Option<bool>,
    pub activewindow: Option<bool>,
    pub pid: Option<String>,
    pub imagename: Option<String>,
    pub windowtitle: Option<String>,
    pub session: Option<String>,
    pub user: Option<String>,
    pub monitor: Option<String>,
}

/// Section 12 (Table 7) keylog event.
pub struct KeyEvent {
    pub time: String, // canonical ts
    pub pid: Option<String>,
    pub imagename: Option<String>,
    pub windowtitle: Option<String>,
    pub keys: String,
}

pub struct KeyCapture {
    pub starttime: String,
    pub endtime: Option<String>,
    pub user: Option<String>,
    pub events: Vec<KeyEvent>,
}

pub struct PackageManager {
    root: PathBuf, // absolute: downloads/<RootFolder>
    // Retained per the module contract (ownership identity, .rcmtarget);
    // read again only when the session layer (SPEC §5) consumes it.
    #[allow(dead_code)]
    instance_id: String,
    write_lock: Mutex<()>, // serializes ALL package writes
    // (batch_ts, rel_path) -> (abs_path, CollectedMeta); see SPEC §4 wire protocol
    meta_cache: Mutex<MetaCache>,
    // Chunk-slot staleness TTL in seconds (seeded from
    // config.rcm.stale_slot_ttl_secs); atomic so tests can shrink it
    // hermetically without backdating file mtimes.
    stale_ttl_secs: std::sync::atomic::AtomicU64,
}

/// Hard cap on wire-protocol metadata cache entries
/// (config.rcm.meta_cache_cap): a hostile agent that announces metadata but
/// never sends data must not grow server memory without bound. Eviction is
/// FIFO (oldest announced first) and is a silent-degradation path: the
/// evicted file's sidecar simply gets NONE times. One WARN is logged per
/// eviction burst (component "agent").
fn meta_cache_cap() -> usize {
    config().rcm.meta_cache_cap
}

struct MetaCache {
    map: HashMap<(String, String), (String, CollectedMeta)>,
    order: VecDeque<(String, String)>, // FIFO insertion order
    warned: bool,                      // one WARN per eviction burst
}

impl MetaCache {
    fn new() -> Self {
        MetaCache {
            map: HashMap::new(),
            order: VecDeque::new(),
            warned: false,
        }
    }

    /// Safety net against FIFO-order drift: whenever `order` grows past
    /// twice the cap, rebuild it retaining only keys still present in
    /// `map` (preserving FIFO). Normal operation keeps the two in sync
    /// (take removes its key from both); this bounds the damage of any
    /// path that ever lets them diverge.
    fn compact_order(&mut self) {
        if self.order.len() > 2 * meta_cache_cap() {
            let map = &self.map;
            self.order.retain(|k| map.contains_key(k));
        }
    }
}

/// Lock a mutex, recovering from poisoning. The guarded state stays
/// consistent across panics (mutations are single infallible operations),
/// so a poisoned lock must not cascade one panic into total failure.
fn lock_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn or_none(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "NONE".to_string())
}

fn bool_or_none(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "True",
        Some(false) => "False",
        None => "NONE",
    }
}

/// Compute (md5, sha256) of a file, streamed (REQ-18.2.1).
fn hash_file(path: &Path) -> Result<(String, String), RcmError> {
    let mut f = std::fs::File::open(path)?;
    let mut md5 = Md5::new();
    let mut sha = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha.update(&buf[..n]);
    }
    Ok((hex::encode(md5.finalize()), hex::encode(sha.finalize())))
}

/// Parse a chunk-transfer state file: EXACTLY three comma-separated u64
/// fields `next_idx,total_chunks,part_len`. Anything else (including the
/// legacy two-field format) is rejected as corrupt.
/// Maximum number of concurrent in-flight chunked transfers of the SAME
/// intended final path (per-transfer slots ".part", ".part.1" ...).
/// Sourced from config.rcm.chunk_slots.
fn max_chunk_slots() -> u64 {
    config().rcm.chunk_slots as u64
}

/// Slot part/state paths for an intended final path: slot 0 is
/// "<X>.part"/"<X>.part.state", slot n is "<X>.part.<n>"/"<X>.part.<n>.state".
fn chunk_slot_paths(intended: &Path, slot: u64) -> (PathBuf, PathBuf) {
    let mut part_os = intended.as_os_str().to_os_string();
    if slot == 0 {
        part_os.push(".part");
    } else {
        part_os.push(format!(".part.{}", slot));
    }
    let part = PathBuf::from(part_os);
    let mut state_os = part.as_os_str().to_os_string();
    state_os.push(".state");
    (part, PathBuf::from(state_os))
}

/// Does a file NAME match a chunk-transfer slot artifact: "<X>.part",
/// "<X>.part.state" (slot 0) or "<X>.part.<n>", "<X>.part.<n>.state"
/// (slot n, n = digits)? Shared by the manifest exclusion rule and the
/// stale-slot reaper.
pub(crate) fn is_chunk_slot_name(name: &str) -> bool {
    if name.ends_with(".part") || name.ends_with(".part.state") {
        return true;
    }
    let core = name.strip_suffix(".state").unwrap_or(name);
    if let Some(pos) = core.rfind(".part.") {
        let digits = &core[pos + ".part.".len()..];
        return !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// A chunk-slot state file older than the TTL is STALE: no graceful
/// transfer pauses that long between chunks, so the transfer must be
/// considered abandoned (server restart, dead agent) and the slot reaps.
/// The TTL comes from config.rcm.stale_slot_ttl_secs.

/// Reap chunk-transfer slot artifacts left under downloads/ by abandoned
/// transfers. Called at package OPEN with the SAME staleness TTL rule as
/// the chunk-0 slot scan: only artifacts whose RELEVANT mtime is older
/// than `ttl` are abandoned debris - for a `.part[.n].state` pair the
/// state file's mtime decides for both, a state-less orphan `.part[.n]`
/// stands on its own mtime. Fresh artifacts may belong to a LIVE transfer
/// owned by another manager (second process, CLI tool, direct API use)
/// and are NEVER touched. Files carrying a metadata sidecar are COMMITTED
/// collected evidence (REQ-8.1.2) and are never reaped. Each reap is
/// WARN-logged (component "agent"). Best-effort: failures are skipped.
fn reap_slot_artifacts_at_open(root: &Path, ttl: std::time::Duration) {
    let age_exceeds = |path: &Path| -> bool {
        path.symlink_metadata()
            .ok()
            .and_then(|md| md.modified().ok())
            .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
            .map_or(false, |age| age > ttl)
    };
    let reap = |root: &Path, rel: &str, path: &Path| {
        if std::fs::remove_file(path).is_ok() {
            let _ = logs::log(
                root,
                "rcm-server",
                "agent",
                "WARN",
                &format!(
                    "reaped abandoned transfer slot artifact at package open (older than {:?}): {}",
                    ttl, rel
                ),
            );
        }
    };
    let downloads = root.join("downloads");
    let mut stack = vec![downloads];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let ft = match entry.file_type() {
                Ok(f) => f,
                Err(_) => continue,
            };
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            // Never follow or remove symlinks/foreign special files.
            if !ft.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_chunk_slot_name(&name) {
                continue;
            }
            let rel = match path.strip_prefix(root) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            let dl = match rel.strip_prefix("downloads/") {
                Some(d) => d,
                None => continue,
            };
            // Committed evidence (has a metadata sidecar) is never reaped.
            let sidecar = root
                .join("downloads.metadata")
                .join(format!("{}.RCM.xml", dl));
            if sidecar.symlink_metadata().is_ok() {
                continue;
            }
            if let Some(part_name) = name.strip_suffix(".state") {
                // State file: its mtime classifies the WHOLE pair. Fresh
                // state -> a live transfer owns the slot; keep part+state.
                if !age_exceeds(&path) {
                    continue;
                }
                // Stale pair: reap the state and its .part (the part only
                // when it carries no sidecar of its own and is a regular
                // file - never remove a symlink or committed evidence).
                let part_path = path.with_file_name(part_name);
                let part_rel = rel.strip_suffix(".state").unwrap_or(&rel).to_string();
                let part_sidecar = root
                    .join("downloads.metadata")
                    .join(format!("{}.RCM.xml", part_rel.strip_prefix("downloads/").unwrap_or(&part_rel)));
                let part_is_plain_file = part_path
                    .symlink_metadata()
                    .map_or(false, |md| md.file_type().is_file());
                if part_is_plain_file && part_sidecar.symlink_metadata().is_err() {
                    reap(root, &part_rel, &part_path);
                }
                reap(root, &rel, &path);
            } else {
                // .part[.n] without a matching state handled above: an
                // ORPHAN. When a state sibling exists the pair is decided
                // by the state's mtime - never reap the part out from
                // under a live transfer here.
                let mut state_os = path.as_os_str().to_os_string();
                state_os.push(".state");
                if Path::new(&state_os).symlink_metadata().is_ok() {
                    continue;
                }
                // State-less orphan: its own mtime decides.
                if !age_exceeds(&path) {
                    continue;
                }
                reap(root, &rel, &path);
            }
        }
    }
}

/// Transfer ids are embedded verbatim in the 4-field chunk-state file:
/// reject any id that could corrupt the framing (','), smuggle control
/// characters into the state file, or carry leading/trailing whitespace
/// (parse_chunk_state trims the state line, so a padded id would never
/// match again and the slot would wedge).
fn validate_transfer_id(tid: &str) -> Result<(), RcmError> {
    if tid.contains(',') || tid.chars().any(char::is_control) || tid != tid.trim() {
        return Err(RcmError(format!("invalid transfer id: {:?}", tid)));
    }
    Ok(())
}

/// Parse a chunk-state file: EXACTLY 4 fields
/// "next_idx,total_chunks,part_len,transfer_id". Anything else - including
/// the legacy 3-field form - is corrupt and never treated as proof of an
/// in-flight transfer.
fn parse_chunk_state(raw: &str) -> Result<(u64, u64, u64, String), RcmError> {
    let fields: Vec<&str> = raw.trim().split(',').collect();
    if fields.len() != 4 {
        return Err(RcmError(format!(
            "corrupt transfer state (want 4 fields next,total,len,transfer_id): {:?}",
            raw
        )));
    }
    let mut nums = [0u64; 3];
    for (i, f) in fields[..3].iter().enumerate() {
        nums[i] = f
            .trim()
            .parse::<u64>()
            .map_err(|_| RcmError(format!("corrupt transfer state: {:?}", raw)))?;
    }
    if nums[0] == 0 || nums[0] > nums[1] {
        return Err(RcmError(format!(
            "corrupt transfer state (next {} out of range for total {}): {:?}",
            nums[0], nums[1], raw
        )));
    }
    let tid = fields[3].to_string();
    validate_transfer_id(&tid)
        .map_err(|_| RcmError(format!("corrupt transfer state (bad transfer id): {:?}", raw)))?;
    Ok((nums[0], nums[1], nums[2], tid))
}

/// Canonical timestamp shape (REQ-4.2.1/4.2.2), accepting 3-7 fractional
/// digits: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,7}Z$`.
fn is_canonical_ts(s: &str) -> bool {
    let b = s.as_bytes();
    let n = b.len();
    if !(24..=28).contains(&n) {
        return false;
    }
    for &i in &[0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !b[i].is_ascii_digit() {
            return false;
        }
    }
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':'
        || b[19] != b'.'
    {
        return false;
    }
    if b[n - 1] != b'Z' {
        return false;
    }
    b[20..n - 1].iter().all(|c| c.is_ascii_digit())
}

impl PackageManager {
    fn new(root: PathBuf, instance_id: &str) -> Self {
        let pm = PackageManager {
            root,
            instance_id: instance_id.to_string(),
            write_lock: Mutex::new(()),
            meta_cache: Mutex::new(MetaCache::new()),
            stale_ttl_secs: std::sync::atomic::AtomicU64::new(config().rcm.stale_slot_ttl_secs),
        };
        // Package-open sweep: reap STALE slot artifacts only (same TTL as
        // the chunk-0 scan, shared via stale_ttl_secs so the test-only
        // override governs both paths) - fresh artifacts may be a LIVE
        // transfer owned by another manager and must survive.
        let ttl = std::time::Duration::from_secs(
            pm.stale_ttl_secs
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        reap_slot_artifacts_at_open(&pm.root, ttl);
        pm
    }

    /// The standard package subdirs (idempotent, race-tolerant).
    fn ensure_tree(root: &Path) -> Result<(), RcmError> {
        paths::ensure_dir(root, &["downloads"])?;
        paths::ensure_dir(root, &["downloads.metadata"])?;
        paths::ensure_dir(root, &["logs"])?;
        paths::ensure_dir(root, &["output", "screenshots"])?;
        paths::ensure_dir(root, &["output", "keylogger"])?;
        Ok(())
    }

    /// Shared initialization for a freshly allocated (or claimed empty)
    /// package folder: standard subdirs, collision log, fingerprint seed.
    /// The .rcmtarget marker MUST already be in place (it is written
    /// immediately after folder creation, before this runs).
    fn init_new_package(
        root: PathBuf,
        hostname: &str,
        instance_id: &str,
        name: &str,
        cand: &str,
        n: u64,
    ) -> Result<Arc<Self>, RcmError> {
        Self::ensure_tree(&root)?;
        let pm = Arc::new(Self::new(root, instance_id));
        if n > 0 {
            let _ = pm.log(
                "package",
                "WARN",
                &format!(
                    "root folder collision for '{}': allocated '{}'",
                    name, cand
                ),
            );
        }
        // Seed the fingerprint (SPEC §5.3): uid ABSENT - insufficient data
        // during active collection (Table 1). Session registration enriches
        // this via update_fingerprint.
        let seed = fingerprint::FingerprintEntry {
            target: "machine".into(),
            fp_type: "os".into(),
            version: 1,
            uid: None,
            fields: vec![
                (
                    "hostname".into(),
                    if hostname.is_empty() {
                        "NONE".into()
                    } else {
                        hostname.to_string()
                    },
                ),
                ("usertag".into(), "NONE".into()),
                (
                    "private_rcm_computerid".into(),
                    instance_id.to_string(),
                ),
            ],
        };
        fingerprint::upsert_entry(&pm.root, &seed)?;
        Ok(pm)
    }

    /// REQ-3.1: open or create the package under `base` (e.g.
    /// Path::new("downloads")). Root folder = sanitize_root_name(hostname);
    /// empty -> sanitize_component(instance_id). Collision (REQ-3.1.7): an
    /// existing folder whose .rcmtarget marker names a DIFFERENT instance_id
    /// -> try "<name>.1", "<name>.2", ... and log the collision.
    pub fn create_or_open(
        base: &Path,
        hostname: &str,
        instance_id: &str,
    ) -> Result<Arc<Self>, RcmError> {
        if let Ok(md) = base.symlink_metadata() {
            if md.file_type().is_symlink() {
                return Err(RcmError(format!(
                    "base dir is a symlink: {}",
                    base.display()
                )));
            }
        }
        std::fs::create_dir_all(base)?;

        let mut name = paths::sanitize_root_name(hostname);
        if name.is_empty() {
            name = paths::sanitize_component(instance_id);
        }
        if name.is_empty() {
            name = "unknown-target".to_string();
        }

        let mut n = 0u64;
        macro_rules! race_trace {
            ($($a:tt)*) => {
                if std::env::var_os("RCM_TRACE_RACE").is_some() {
                    eprintln!("[trace {:?} {}] {}", std::thread::current().id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or(0), format!($($a)*));
                }
            };
        }
        // Bound same-candidate re-evaluations: racing claims legitimately
        // re-check the SAME candidate, but a hostile/foreign artifact that
        // never resolves (e.g. a dangling symlink at the marker path) must
        // not spin this loop at 100% CPU - after 3 re-evaluations, move on
        // to the next suffix.
        let mut reevals = 0u32;
        macro_rules! reevaluate_same_candidate {
            () => {{
                // Back off between re-evaluations: a racing owner only needs
                // microseconds-to-milliseconds to finish its marker write,
                // but on loaded filesystems a tight spin exhausts the bound
                // inside that window and wrongly suffixes the folder.
                reevals += 1;
                if reevals >= 60 {
                    reevals = 0;
                    n += 1;
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                continue;
            }};
        }
        loop {
            let cand = if n == 0 {
                name.clone()
            } else {
                format!("{}.{}", name, n)
            };
            let root = base.join(&cand);
            match root.symlink_metadata() {
                Ok(md) => {
                    // A symlink or non-dir here is hostile/foreign; never
                    // follow it, just move to the next candidate name.
                    if md.file_type().is_symlink() || !md.is_dir() {
                        race_trace!("suffix: symlink/non-dir at {}", cand);
                        reevals = 0;
                        n += 1;
                        continue;
                    }
                    let marker_path = root.join(".rcmtarget");
                    let marker = match std::fs::read_to_string(&marker_path) {
                        Ok(m) => Some(m),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                        Err(e) => return Err(e.into()),
                    };
                    if marker.as_deref().map(str::trim) == Some(instance_id) {
                        // Our target already owns this folder. Guarantee the
                        // standard tree (a racing claimant may still be
                        // mid-init; ensure_dir is idempotent + race-safe).
                        Self::ensure_tree(&root)?;
                        return Ok(Arc::new(Self::new(root, instance_id)));
                    }
                    match marker {
                        // Marker file exists but is empty: the claiming
                        // thread is mid-write, or crashed between create and
                        // write. Take the marker over (same-target racers
                        // write identical content). A confirm mismatch is
                        // TRANSIENT (another claim in flight): re-evaluate
                        // the same candidate instead of suffixing.
                        Some(m) if m.trim().is_empty() => {
                            // Never write through a symlinked marker.
                            if marker_path
                                .symlink_metadata()
                                .map(|md| md.file_type().is_symlink())
                                .unwrap_or(false)
                            {
                                reevals = 0;
                                n += 1;
                                continue;
                            }
                            // Direct write (no tmp+rename): concurrent
                            // takeovers of the SAME target write identical
                            // bytes, and a tmp file would race with another
                            // takeover's cleanup.
                            std::fs::write(
                                &marker_path,
                                format!("{}\n", instance_id).as_bytes(),
                            )?;
                            let confirm = std::fs::read_to_string(&marker_path)
                                .unwrap_or_default();
                            if confirm.trim() == instance_id {
                                return Self::init_new_package(
                                    root, hostname, instance_id, &name, &cand, n,
                                );
                            }
                            reevaluate_same_candidate!();
                        }
                        // Marker for a different target: genuine collision.
                        Some(_) => {}
                        // No marker at all: claimable only when the folder
                        // is otherwise EMPTY (a racer between create_dir and
                        // marker write, or a crashed init). A non-empty
                        // unmarked folder is foreign.
                        None => {
                            // The marker and its in-flight tmp are excluded
                            // (a racer's atomic claim write may appear
                            // between our reads).
                            let has_entries = std::fs::read_dir(&root)?
                                .filter_map(|e| e.ok())
                                .any(|e| {
                                    let n = e.file_name();
                                    n != ".rcmtarget" && n != ".rcmtarget.tmp"
                                });
                            if !has_entries {
                                match std::fs::OpenOptions::new()
                                    .write(true)
                                    .create_new(true)
                                    .open(&marker_path)
                                {
                                    Ok(mut f) => {
                                        use std::io::Write;
                                        f.write_all(
                                            format!("{}\n", instance_id).as_bytes(),
                                        )?;
                                        f.sync_all()?;
                                        // Confirm we still own the claim.
                                        let confirm =
                                            std::fs::read_to_string(&marker_path)
                                                .unwrap_or_default();
                                        if confirm.trim() == instance_id {
                                            return Self::init_new_package(
                                                root, hostname, instance_id, &name,
                                                &cand, n,
                                            );
                                        }
                                        // Transient: re-evaluate.
                                        reevaluate_same_candidate!();
                                    }
                                    Err(e)
                                        if e.kind()
                                            == std::io::ErrorKind::AlreadyExists =>
                                    {
                                        // A SYMLINK at the marker path (in
                                        // particular a dangling one: reads
                                        // return ENOENT, so this folder was
                                        // judged empty, but create_new fails
                                        // AlreadyExists forever) or a marker
                                        // we still cannot inspect: never
                                        // re-evaluate this candidate - that
                                        // spins at 100% CPU.
                                        match marker_path.symlink_metadata() {
                                            Ok(md)
                                                if md.file_type().is_symlink() =>
                                            {
                                                reevals = 0;
                                                n += 1;
                                                continue;
                                            }
                                            Err(_) => {
                                                reevals = 0;
                                                n += 1;
                                                continue;
                                            }
                                            // Lost the claim race to a real
                                            // marker; re-evaluate (bounded).
                                            Ok(_) => reevaluate_same_candidate!(),
                                        }
                                    }
                                    Err(e) => return Err(e.into()),
                                }
                            }
                        }
                    }
                    if marker.is_some() {
                        race_trace!("suffix: foreign marker {:?} at {} (want {})", marker.as_deref().map(|m| m.trim().chars().take(24).collect::<String>()), cand, instance_id);
                    } else {
                        race_trace!("suffix: unresolvable after reevals at {}", cand);
                    }
                    reevals = 0;
                    n += 1; // folder belongs to a different target
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match std::fs::create_dir(&root) {
                        Ok(()) => {
                            // TEST-ONLY: widen the race window when asked.
                            if let Ok(ms) = std::env::var("RCM_RACE_DELAY_MS") {
                                std::thread::sleep(std::time::Duration::from_millis(
                                    ms.parse().unwrap_or(0),
                                ));
                            }
                            // Write the private ownership marker IMMEDIATELY
                            // with O_EXCL, before any other tree setup: a
                            // concurrent create_or_open for the same target
                            // must find the marker already in place,
                            // otherwise the racer suffixes the folder and
                            // one target gets split into N packages.
                            match xml::atomic_write(
                                &root.join(".rcmtarget"),
                                format!("{}\n", instance_id).as_bytes(),
                            ) {
                                Ok(()) => {
                                    // Confirm we still own the marker (a
                                    // racing takeover would show here).
                                    let confirm =
                                        std::fs::read_to_string(root.join(".rcmtarget"))
                                            .unwrap_or_default();
                                    if confirm.trim() != instance_id {
                                        reevaluate_same_candidate!();
                                    }
                                }
                                // A racer claimed the marker path between
                                // our create_dir and the rename: re-evaluate.
                                // Genuine IO errors propagate instead.
                                Err(e) if e.to_string().contains("racing writer") => {
                                    reevaluate_same_candidate!();
                                }
                                Err(e) => return Err(e),
                            }
                            race_trace!("owner path init at {}", cand);
                            return Self::init_new_package(
                                root, hostname, instance_id, &name, &cand, n,
                            );
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            // Lost the race; re-evaluate the marker (bounded).
                            reevaluate_same_candidate!();
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Open an existing package by root folder NAME (for API use after
    /// restart). The name is validated against path traversal.
    pub fn open_by_root_name(base: &Path, root_name: &str) -> Result<Arc<Self>, RcmError> {
        if root_name.is_empty()
            || root_name.contains(['/', '\\'])
            || root_name.chars().all(|c| c == '.')
        {
            return Err(RcmError(format!("invalid root name: {:?}", root_name)));
        }
        let root = base.join(root_name);
        let md = root
            .symlink_metadata()
            .map_err(|e| RcmError(format!("open package {}: {}", root_name, e)))?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(RcmError(format!("not a package directory: {}", root_name)));
        }
        let marker =
            std::fs::read_to_string(root.join(".rcmtarget")).unwrap_or_default();
        let instance_id = marker.trim().to_string();
        Ok(Arc::new(Self::new(root, &instance_id)))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn root_name(&self) -> String {
        self.root
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// REQ-8.1.8/Section 13: after reconstructing components, log a WARN
    /// (component "agent") for each component that received the `_` prefix
    /// for being a reserved device name. Caller must hold `write_lock`
    /// (uses logs::log directly to avoid re-locking).
    fn log_reserved_substitutions(&self, original: &str, comps: &[String]) {
        // Raw components of the source path (both separator forms). A genuine
        // REQ-8.1.8 substitution stores reserved name X as _X; a target file
        // legitimately named _X must NOT be logged as a substitution, so the
        // unprefixed form must actually appear in the source path.
        let raw: std::collections::HashSet<&str> = original
            .split(['/', '\\'])
            .filter(|s| !s.is_empty())
            .collect();
        for c in comps {
            if let Some(stripped) = c.strip_prefix('_') {
                if paths::is_reserved_device_name(stripped) && raw.contains(stripped) {
                    let _ = logs::log(
                        &self.root,
                        "rcm-server",
                        "agent",
                        "WARN",
                        &format!(
                            "reserved device-name substitution (REQ-8.1.8): '{}' stored as '{}' for {}",
                            stripped, c, original
                        ),
                    );
                }
            }
        }
    }

    /// Shared tail of store_collected / chunk finalization: build the
    /// sidecar for the just-stored file. `stored_rel` is relative to
    /// `downloads/` ('/' seps, counter suffix already applied).
    fn write_collected_sidecar(
        &self,
        original_path: &str,
        stored_rel: &str,
        abs: &Path,
        meta: &CollectedMeta,
    ) -> Result<(), RcmError> {
        let (md5, sha256) = hash_file(abs)?;
        let (name, dirname) = paths::split_name_dirname(original_path);
        let fm = sidecar::FileMeta {
            name,
            dirname,
            size: abs.metadata()?.len(),
            md5,
            sha256,
            modified: meta.modified.clone(),
            accessed: meta.accessed.clone(),
            created: meta.created.clone(),
            owner: meta.owner.clone(),
            group: meta.group.clone(),
        };
        sidecar::write_sidecar(&self.root, stored_rel, &fm, &xml::now_ts())?;
        Ok(())
    }

    /// §8: store collected file + sidecar. Returns the package-relative
    /// stored path ('/' seps, e.g. "downloads/C/WINDOWS/plAns.txt").
    pub fn store_collected(
        &self,
        original_path: &str,
        bytes: &[u8],
        meta: &CollectedMeta,
    ) -> Result<String, RcmError> {
        let _g = lock_recover(&self.write_lock);
        // Validated reconstruction: filename-less paths (bare drive roots,
        // UNC share roots, trailing separators) are rejected BEFORE any
        // artifact is created (leaf-file tree poisoning).
        let comps = paths::reconstruct_collected_components(original_path)?;
        self.log_reserved_substitutions(original_path, &comps);
        let downloads = paths::ensure_dir(&self.root, &["downloads"])?;
        let parent: Vec<&str> = comps[..comps.len() - 1].iter().map(String::as_str).collect();
        let dir = paths::ensure_dir(&downloads, &parent)?;

        // REQ-3.4.3/3.4.5: allocate the final name first (O_EXCL), then
        // atomically replace the empty placeholder via .tmp+rename so a
        // consumer never observes a partially written final file.
        let (final_path, placeholder) = counters::download_file(&dir, &comps[comps.len() - 1])?;
        drop(placeholder);
        if let Err(e) = xml::atomic_write(&final_path, bytes) {
            // REQ-16.2: a failed collection leaves no misleading artifacts.
            let _ = std::fs::remove_file(&final_path);
            return Err(e);
        }

        let final_name = final_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| RcmError("bad stored filename".into()))?;
        let stored_rel = if parent.is_empty() {
            final_name.clone()
        } else {
            format!("{}/{}", parent.join("/"), final_name)
        };
        if let Err(e) =
            self.write_collected_sidecar(original_path, &stored_rel, &final_path, meta)
        {
            // REQ-16.2: never leave a data file without its sidecar (e.g.
            // when the sidecar name exceeds NAME_MAX but the data name
            // does not). Best-effort cleanup before returning the error.
            let _ = std::fs::remove_file(&final_path);
            return Err(e);
        }
        Ok(format!("downloads/{}", stored_rel))
    }

    /// §8 + REQ-6.3.5: chunked collected file with PER-TRANSFER slots.
    /// Every transfer carries a `transfer_id` (the command's request id on
    /// the wire path); concurrent transfers of the SAME intended final path
    /// are kept apart by claiming distinct slot files
    /// "<X>.part"/"<X>.part.state" … "<X>.part.7"/"<X>.part.7.state" whose
    /// 4-field state ("next_idx,total_chunks,part_len,transfer_id") names
    /// the owning transfer. Later chunks append in strict order to the slot
    /// OWNED by their transfer id (mismatch -> Err, .part kept; unknown id
    /// -> Err, foreign slots never touched). The final chunk renames that
    /// transfer's .part to the final name with counter allocation per
    /// REQ-3.4.3/3.4.5 (two concurrent same-path transfers finalize to "X"
    /// and "X.1"), deletes ITS state file and writes the sidecar. Ok(true)
    /// when finalized.
    ///
    /// Chunk-0 slot scan:
    ///   1. parseable state with OUR transfer id: same total -> legitimate
    ///      retry (truncate + restart); different total -> error (same id,
    ///      different transfer shape).
    ///   2. parseable state with a DIFFERENT transfer id: another live
    ///      transfer owns the slot - try the next one. EXCEPTION: a state
    ///      file older than the staleness TTL marks an ABANDONED transfer -
    ///      reap part+state (WARN-logged) and treat the slot as free.
    ///   3. .part (or orphan state) exists but NO parseable state: committed
    ///      evidence (e.g. a collected file legitimately named "X.part") -
    ///      NEVER deleted or overwritten; try the next slot.
    ///   4. neither exists: claim the slot (create .part O_EXCL, write
    ///      state).
    ///   5. all chunk slots busy -> error.
    pub fn store_collected_chunk(
        &self,
        original_path: &str,
        chunk_idx: u64,
        total_chunks: u64,
        bytes: &[u8],
        transfer_id: &str,
        meta: &CollectedMeta,
    ) -> Result<bool, RcmError> {
        let _g = lock_recover(&self.write_lock);
        if total_chunks == 0 || chunk_idx >= total_chunks {
            return Err(RcmError(format!(
                "invalid chunk indices {}/{}",
                chunk_idx, total_chunks
            )));
        }
        validate_transfer_id(transfer_id)?;
        let comps = paths::reconstruct_collected_components(original_path)?;
        let downloads = paths::ensure_dir(&self.root, &["downloads"])?;
        let parent: Vec<&str> = comps[..comps.len() - 1].iter().map(String::as_str).collect();
        let dir = paths::ensure_dir(&downloads, &parent)?;

        let intended = dir.join(&comps[comps.len() - 1]);

        use std::io::Write;
        let new_len: u64;
        let part: PathBuf;
        let state: PathBuf;
        if chunk_idx == 0 {
            // REQ-8.1.8 substitutions logged once per transfer.
            self.log_reserved_substitutions(original_path, &comps);
            // Pass 1 prefers our own in-flight slot (a retry must reuse it
            // even when an earlier slot has since freed up); pass 2 claims
            // the first provably unused slot.
            let mut retry_slot: Option<(PathBuf, PathBuf)> = None;
            let mut free_slot: Option<(PathBuf, PathBuf)> = None;
            for slot in 0..max_chunk_slots() {
                let (sp, ss) = chunk_slot_paths(&intended, slot);
                if let Ok(raw) = std::fs::read_to_string(&ss) {
                    if let Ok((_next, stotal, _len, stid)) = parse_chunk_state(&raw) {
                        if stid == transfer_id {
                            if stotal != total_chunks {
                                return Err(RcmError(format!(
                                    "chunk-0 restart with different total ({} != {}) for transfer {:?} of {}",
                                    total_chunks,
                                    stotal,
                                    transfer_id,
                                    sp.display()
                                )));
                            }
                            retry_slot = Some((sp, ss));
                            break;
                        }
                        // Another transfer owns this slot. A state file
                        // older than the staleness TTL marks an ABANDONED
                        // transfer (no graceful transfer pauses that long
                        // between chunks): reap part+state and fall through
                        // to the free-slot check.
                        let ttl = std::time::Duration::from_secs(
                            self.stale_ttl_secs
                                .load(std::sync::atomic::Ordering::Relaxed),
                        );
                        let stale = ss
                            .symlink_metadata()
                            .ok()
                            .and_then(|md| md.modified().ok())
                            .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
                            .map_or(false, |age| age > ttl);
                        if !stale {
                            // Another LIVE transfer owns this slot.
                            continue;
                        }
                        let _ = std::fs::remove_file(&sp);
                        let _ = std::fs::remove_file(&ss);
                        let _ = logs::log(
                            &self.root,
                            "rcm-server",
                            "agent",
                            "WARN",
                            &format!(
                                "reaped stale transfer slot (state older than {:?}): {}",
                                ttl,
                                ss.display()
                            ),
                        );
                    }
                }
                // No parseable state: any artifact here (.part OR orphan
                // state) is committed evidence / foreign - never touch it.
                if sp.symlink_metadata().is_ok() || ss.symlink_metadata().is_ok() {
                    continue;
                }
                if free_slot.is_none() {
                    free_slot = Some((sp, ss));
                }
            }
            match (retry_slot, free_slot) {
                (Some((sp, ss)), _) => {
                    // Legitimate same-id retry: truncate in place, then run
                    // the crash-safe sequence state(len=0) -> bytes ->
                    // state(len) so a crash mid-write replays cleanly.
                    if let Ok(md) = sp.symlink_metadata() {
                        if md.file_type().is_symlink() {
                            return Err(RcmError(format!(
                                "refusing to write through symlink: {}",
                                sp.display()
                            )));
                        }
                    }
                    let f = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&sp)?;
                    drop(f);
                    xml::atomic_write(
                        &ss,
                        format!("1,{},0,{}", total_chunks, transfer_id).as_bytes(),
                    )?;
                    let mut f = std::fs::OpenOptions::new().append(true).open(&sp)?;
                    f.write_all(bytes)?;
                    f.sync_all()?;
                    part = sp;
                    state = ss;
                }
                (None, Some((sp, ss))) => {
                    // Claim a free slot: create the .part O_EXCL first, then
                    // the state naming this transfer.
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&sp)
                        .map_err(|e| {
                            RcmError(format!("claim transfer slot {}: {}", sp.display(), e))
                        })?;
                    f.write_all(bytes)?;
                    f.sync_all()?;
                    part = sp;
                    state = ss;
                }
                (None, None) => {
                    return Err(RcmError(format!(
                        "too many concurrent transfers of {}",
                        original_path
                    )));
                }
            }
            new_len = bytes.len() as u64;
        } else {
            // Find the slot whose state names OUR transfer id; never append
            // to a foreign slot.
            let mut found: Option<(PathBuf, PathBuf, u64, u64, u64)> = None;
            for slot in 0..max_chunk_slots() {
                let (sp, ss) = chunk_slot_paths(&intended, slot);
                if let Ok(raw) = std::fs::read_to_string(&ss) {
                    if let Ok((next, total, len, stid)) = parse_chunk_state(&raw) {
                        if stid == transfer_id {
                            found = Some((sp, ss, next, total, len));
                            break;
                        }
                    }
                }
            }
            let (sp, ss, next, total, expected_len) = found.ok_or_else(|| {
                RcmError(format!(
                    "no in-flight transfer with this id ({:?}) for {}",
                    transfer_id, original_path
                ))
            })?;
            // Strict in-order enforcement; on mismatch the .part is kept.
            if total != total_chunks {
                return Err(RcmError(format!(
                    "chunk count changed mid-transfer ({} != {})",
                    total_chunks, total
                )));
            }
            if chunk_idx != next {
                return Err(RcmError(format!(
                    "out-of-order chunk: got {}, expected {}",
                    chunk_idx, next
                )));
            }
            // Length cross-check against the state: a crash between the
            // append and the state write leaves .part LONGER than recorded
            // - truncate back for an idempotent replay of this chunk. A
            // SHORTER .part means external corruption: refuse.
            let actual_len = sp.symlink_metadata()?.len();
            if actual_len > expected_len {
                let f = std::fs::OpenOptions::new().write(true).open(&sp)?;
                f.set_len(expected_len)?;
                drop(f);
            } else if actual_len < expected_len {
                return Err(RcmError(format!(
                    "transfer .part is shorter than recorded state ({} < {}): {}",
                    actual_len,
                    expected_len,
                    sp.display()
                )));
            }
            let mut f = std::fs::OpenOptions::new().append(true).open(&sp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            new_len = expected_len + bytes.len() as u64;
            part = sp;
            state = ss;
        }
        xml::atomic_write(
            &state,
            format!(
                "{},{},{},{}",
                chunk_idx + 1,
                total_chunks,
                new_len,
                transfer_id
            )
            .as_bytes(),
        )?;

        if chunk_idx + 1 < total_chunks {
            return Ok(false);
        }

        // Final chunk: allocate the REQ-3.4.3 counter name with O_EXCL,
        // then rename .part over the empty placeholder (atomic on POSIX;
        // the placeholder is ours, so no foreign content is destroyed).
        let (final_path, placeholder) =
            counters::download_file(&dir, &comps[comps.len() - 1])?;
        drop(placeholder);
        std::fs::rename(&part, &final_path)?;
        if let Err(e) = std::fs::remove_file(&state) {
            if e.kind() != std::io::ErrorKind::NotFound {
                let _ = logs::log(
                    &self.root,
                    "rcm-server",
                    "agent",
                    "WARN",
                    &format!(
                        "finalized transfer but could not remove state file {}: {}",
                        state.display(),
                        e
                    ),
                );
            }
        }

        let final_name = final_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| RcmError("bad stored filename".into()))?;
        let stored_rel = if parent.is_empty() {
            final_name
        } else {
            format!("{}/{}", parent.join("/"), final_name)
        };
        if let Err(e) =
            self.write_collected_sidecar(original_path, &stored_rel, &final_path, meta)
        {
            // REQ-16.2: never leave a data file without its sidecar.
            let _ = std::fs::remove_file(&final_path);
            return Err(e);
        }
        Ok(true)
    }

    /// §11: output/screenshots/screenshot.<YYYYMMDD-HHMMSS>.<toolspecific>.<ext>
    /// (+ REQ-3.4.1 counter on collision) and sidecar per REQ-3.3.4/Table 6
    /// (absent keys -> NONE; booleans True/False).
    pub fn store_screenshot(
        &self,
        bytes: &[u8],
        meta: &ScreenshotMeta,
    ) -> Result<String, RcmError> {
        let _g = lock_recover(&self.write_lock);
        let dir = paths::ensure_dir(&self.root, &["output", "screenshots"])?;
        // Empty sanitized components would produce degenerate names like
        // "screenshot.20260106-092133..png" - fall back to sane defaults.
        let tool = paths::sanitize_component(&meta.toolspecific);
        let tool = if tool.is_empty() { "shot".to_string() } else { tool };
        let ext = paths::sanitize_component(&meta.ext);
        let ext = if ext.is_empty() { "png".to_string() } else { ext };
        let stem = format!(
            "screenshot.{}.{}",
            meta.captured_at.format("%Y%m%d-%H%M%S"),
            tool
        );
        let (path, placeholder) = counters::tool_file(&dir, &stem, &ext)?;
        drop(placeholder);
        if let Err(e) = xml::atomic_write(&path, bytes) {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        let fname = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| RcmError("bad screenshot filename".into()))?;

        let mut el = String::from("  <screenshot version=\"1\">\n");
        macro_rules! kv {
            ($k:expr, $v:expr) => {
                el.push_str(&format!(
                    "    <{}>{}</{}>\n",
                    $k,
                    xml::xml_escape(&$v),
                    $k
                ))
            };
        }
        // Table 6 gives originalsize no NONE fallback: OMIT when unknown.
        if let Some(os) = &meta.originalsize {
            kv!("originalsize", os);
        }
        kv!("isfullscreen", bool_or_none(meta.isfullscreen));
        kv!("isminimized", bool_or_none(meta.isminimized));
        kv!("activewindow", bool_or_none(meta.activewindow));
        kv!("pid", or_none(&meta.pid));
        kv!("imagename", or_none(&meta.imagename));
        kv!("windowtitle", or_none(&meta.windowtitle));
        kv!("session", or_none(&meta.session));
        kv!("user", or_none(&meta.user));
        kv!("monitor", or_none(&meta.monitor));
        el.push_str("  </screenshot>\n");
        let doc = xml::xml_doc(&el, &xml::canonical_ts(&meta.captured_at));
        let sidecar_path = dir.join(format!("{}.RCM.xml", fname));
        xml::atomic_write(&sidecar_path, doc.as_bytes())?;

        Ok(format!("output/screenshots/{}", fname))
    }

    /// §12: output/keylogger/keylog.RCM.<counter>.xml (counter always
    /// present, from 0; REQ-3.4.2).
    pub fn store_keylog(&self, captures: &[KeyCapture]) -> Result<String, RcmError> {
        let _g = lock_recover(&self.write_lock);
        let dir = paths::ensure_dir(&self.root, &["output", "keylogger"])?;
        let (path, placeholder, _n) = counters::counted_file(&dir, "keylog.RCM", "xml")?;
        drop(placeholder);

        // Agent-supplied capture times are validated against the canonical
        // timestamp format: they feed element text AND the envelope
        // <timestamp>, so a malformed/hostile value falls back instead of
        // being propagated (starttime -> now, endtime -> NONE).
        let now = xml::now_ts();
        let clean: Vec<(String, Option<String>)> = captures
            .iter()
            .map(|c| {
                let start = if is_canonical_ts(&c.starttime) {
                    c.starttime.clone()
                } else {
                    now.clone()
                };
                let end = c.endtime.clone().filter(|t| is_canonical_ts(t));
                (start, end)
            })
            .collect();

        let mut el = String::from("  <keylog version=\"1\">\n");
        for (cap, (start, end)) in captures.iter().zip(clean.iter()) {
            el.push_str("    <capture>\n");
            el.push_str(&format!(
                "      <starttime>{}</starttime>\n",
                xml::xml_escape(start)
            ));
            el.push_str(&format!(
                "      <endtime>{}</endtime>\n",
                xml::xml_escape(&or_none(end))
            ));
            el.push_str(&format!(
                "      <user>{}</user>\n",
                xml::xml_escape(&or_none(&cap.user))
            ));
            for ev in &cap.events {
                el.push_str("      <event>\n");
                macro_rules! kv {
                    ($k:expr, $v:expr) => {
                        el.push_str(&format!(
                            "        <{}>{}</{}>\n",
                            $k,
                            xml::xml_escape(&$v),
                            $k
                        ))
                    };
                }
                kv!("time", ev.time);
                kv!("pid", or_none(&ev.pid));
                kv!("imagename", or_none(&ev.imagename));
                kv!("windowtitle", or_none(&ev.windowtitle));
                kv!("keys", ev.keys);
                el.push_str("      </event>\n");
            }
            el.push_str("    </capture>\n");
        }
        el.push_str("  </keylog>\n");

        // Document timestamp = when the captured action ended (REQ-4.2.5).
        // Uses the VALIDATED endtime (invalid values already fell back).
        let doc_ts = clean
            .last()
            .and_then(|(_, e)| e.clone())
            .unwrap_or_else(xml::now_ts);
        if let Err(e) = xml::atomic_write(&path, xml::xml_doc(&el, &doc_ts).as_bytes()) {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        let fname = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| RcmError("bad keylog filename".into()))?;
        Ok(format!("output/keylogger/{}", fname))
    }

    pub fn update_fingerprint(
        &self,
        entry: &fingerprint::FingerprintEntry,
    ) -> Result<fingerprint::UpsertOutcome, RcmError> {
        let _g = lock_recover(&self.write_lock);
        fingerprint::upsert_entry(&self.root, entry)
    }

    pub fn custody(
        &self,
        actor: &str,
        action: custody::CustodyAction,
        authorization: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), RcmError> {
        let _g = lock_recover(&self.write_lock);
        custody::append_event(&self.root, actor, action, authorization, details)
    }

    pub fn log(&self, component: &str, level: &str, message: &str) -> Result<(), RcmError> {
        let _g = lock_recover(&self.write_lock);
        logs::log(&self.root, "rcm-server", component, level, message)
    }

    /// Section 17.2 + 17.3: write the next manifest generation, then append
    /// a PACKAGE custody event (custody.RCM.xml is excluded from the
    /// manifest per REQ-17.2.5, so the event does not invalidate it).
    pub fn seal(&self) -> Result<PathBuf, RcmError> {
        let _g = lock_recover(&self.write_lock);
        // REQ-2.4 (SHOULD): record tool deviations as a manifest note.
        let notes = vec![(
            "fingerprint.RCM.xml".to_string(),
            "Tool deviation records per REQ-2.4: see tool CONFORMANCE.md".to_string(),
        )];
        // REQ-17.5.1: the seal is recorded as a Section-13 log entry. It is
        // written BEFORE manifest generation so the log file is hashed into
        // the very generation it announces (appending it afterwards would
        // invalidate that manifest). The write lock makes the pre-computed
        // next-manifest path stable.
        let path = manifest::next_manifest_path(&self.root);
        let fname = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let generation = if fname == "manifest.RCM.xml" {
            0
        } else {
            fname
                .trim_start_matches("manifest.RCM.")
                .trim_end_matches(".xml")
                .parse::<u64>()
                .unwrap_or(0)
        };
        let _ = logs::log(
            &self.root,
            "rcm-server",
            "package",
            "INFO",
            // Written pre-seal (so it is hashed into this generation); the
            // custody PACKAGE event below records the completed seal.
            &format!("sealing manifest generation {}: {}", generation, fname),
        );
        let path = manifest::seal(&self.root, &notes)?;
        custody::append_event(
            &self.root,
            "rcm-server",
            custody::CustodyAction::Package,
            None,
            Some(&format!("Package sealed, manifest generation {}", generation)),
        )?;
        Ok(path)
    }

    pub fn is_sealed(&self) -> bool {
        self.root.join("manifest.RCM.xml").exists()
    }

    pub fn verify(&self) -> Result<Vec<String>, RcmError> {
        // Read-only consistency: take the write lock so verification never
        // observes a package mid-store (partial data file vs. its sidecar,
        // a .part mid-rename, etc.).
        let _g = lock_recover(&self.write_lock);
        manifest::verify(&self.root)
    }

    /// Wire-protocol metadata cache (SPEC §4): record metadata announced by
    /// a `file:meta|` message before the data it describes arrives. Bounded
    /// to the configured cap (config.rcm.meta_cache_cap) entries with FIFO
    /// eviction: a hostile agent flooding announcements cannot grow server
    /// memory without bound.
    pub fn note_file_meta(
        &self,
        batch_ts: &str,
        rel_path: &str,
        abs_path: &str,
        meta: CollectedMeta,
    ) {
        let mut cache = lock_recover(&self.meta_cache);
        let key = (batch_ts.to_string(), rel_path.to_string());
        if !cache.map.contains_key(&key) {
            // Evict the oldest entries until there is room for this one.
            while cache.map.len() >= meta_cache_cap() {
                let oldest = match cache.order.pop_front() {
                    Some(k) => k,
                    None => break,
                };
                if cache.map.remove(&oldest).is_some() && !cache.warned {
                    // One WARN per eviction burst; eviction degrades the
                    // evicted file's sidecar to NONE times (silent
                    // degradation), so it must be visible in the tool log.
                    let _ = logs::log(
                        &self.root,
                        "rcm-server",
                        "agent",
                        "WARN",
                        &format!(
                            "meta cache full ({} entries): evicting oldest announced metadata (FIFO); affected sidecars get NONE times",
                            meta_cache_cap()
                        ),
                    );
                    cache.warned = true;
                }
            }
            cache.order.push_back(key.clone());
        }
        cache.map.insert(key, (abs_path.to_string(), meta));
        cache.compact_order();
    }

    pub fn take_file_meta(
        &self,
        batch_ts: &str,
        rel_path: &str,
    ) -> Option<(String, CollectedMeta)> {
        let mut cache = lock_recover(&self.meta_cache);
        let key = (batch_ts.to_string(), rel_path.to_string());
        let out = cache.map.remove(&key);
        if out.is_some() {
            // Keep `order` in sync: a taken key must not linger as a FIFO
            // ghost, or note+take cycles grow `order` without bound (the
            // VecDeque is small, so a position scan is fine).
            if let Some(pos) = cache.order.iter().position(|k| *k == key) {
                cache.order.remove(pos);
            }
        }
        cache.compact_order();
        // Below the cap again: the eviction burst is over, re-arm the WARN.
        if cache.map.len() < meta_cache_cap() {
            cache.warned = false;
        }
        out
    }

    /// Like `take_file_meta` but NON-destructive: returns a clone of the
    /// cached entry without removing it. Required for chunked transfers,
    /// where every chunk needs the announced abs path + metadata but the
    /// entry may only be evicted once the transfer has finalized.
    pub fn peek_file_meta(
        &self,
        batch_ts: &str,
        rel_path: &str,
    ) -> Option<(String, CollectedMeta)> {
        let cache = lock_recover(&self.meta_cache);
        cache
            .map
            .get(&(batch_ts.to_string(), rel_path.to_string()))
            .cloned()
    }

    #[cfg(test)]
    fn meta_cache_len(&self) -> usize {
        lock_recover(&self.meta_cache).map.len()
    }

    #[cfg(test)]
    fn meta_cache_order_len(&self) -> usize {
        lock_recover(&self.meta_cache).order.len()
    }

    /// Test-only knob for the chunk-slot staleness TTL (avoids backdating
    /// file mtimes in tests).
    #[cfg(test)]
    fn set_stale_slot_ttl(&self, ttl: std::time::Duration) {
        self.stale_ttl_secs
            .store(ttl.as_secs(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> String {
        "2026-01-06T08:11:00.1232010Z".to_string()
    }

    #[test]
    fn create_tree_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let pm = PackageManager::create_or_open(base, "Bingy-Desktop", "inst-1").unwrap();
        assert_eq!(pm.root_name(), "Bingy-Desktop");
        for sub in [
            "downloads",
            "downloads.metadata",
            "logs",
            "output/screenshots",
            "output/keylogger",
        ] {
            assert!(pm.root().join(sub).is_dir(), "missing {}", sub);
        }
        assert_eq!(
            std::fs::read_to_string(pm.root().join(".rcmtarget")).unwrap(),
            "inst-1\n"
        );
        // Fingerprint seeded without uid.
        let fp = std::fs::read_to_string(pm.root().join("fingerprint.RCM.xml")).unwrap();
        assert!(fp.contains("<hostname>Bingy-Desktop</hostname>"));
        assert!(fp.contains("<private_rcm_computerid>inst-1</private_rcm_computerid>"));
        assert!(!fp.contains("<uid>"));

        // Same instance reopens the same folder.
        let pm2 = PackageManager::create_or_open(base, "Bingy-Desktop", "inst-1").unwrap();
        assert_eq!(pm2.root(), pm.root());
    }

    #[test]
    fn collision_allocates_counter_and_logs() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let _pm1 = PackageManager::create_or_open(base, "host_a", "inst-1").unwrap();
        // host:a and host?a both sanitize to host_a but belong to others.
        let pm2 = PackageManager::create_or_open(base, "host:a", "inst-2").unwrap();
        assert_eq!(pm2.root_name(), "host_a.1");
        let pm3 = PackageManager::create_or_open(base, "host?a", "inst-3").unwrap();
        assert_eq!(pm3.root_name(), "host_a.2");
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let log = std::fs::read_to_string(
            pm2.root()
                .join("logs/rcm-server/package")
                .join(&date)
                .join("0000.log"),
        )
        .unwrap();
        assert!(log.contains(" WARN "));
        assert!(log.contains("collision"));
    }

    #[test]
    fn hostname_fallback_to_instance_id() {
        let dir = tempfile::tempdir().unwrap();
        // Undeterminable hostname (nothing usable remains) -> instance id
        // (REQ-3.1.3).
        let pm = PackageManager::create_or_open(dir.path(), "", "inst-x").unwrap();
        assert_eq!(pm.root_name(), "inst-x");
        let pm2 = PackageManager::create_or_open(dir.path(), "...", "inst-y").unwrap();
        assert_eq!(pm2.root_name(), "inst-y");
    }

    #[test]
    fn store_collected_end_to_end_and_counters() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta {
            modified: Some(ts()),
            accessed: None,
            created: None,
            owner: Some("Dr. good".into()),
            group: None,
        };
        let rel = pm
            .store_collected("C:\\WINDOWS\\plAns.txt", b"hello", &meta)
            .unwrap();
        assert_eq!(rel, "downloads/C/WINDOWS/plAns.txt");
        assert_eq!(
            std::fs::read(pm.root().join(&rel)).unwrap(),
            b"hello"
        );
        let sc = pm
            .root()
            .join("downloads.metadata/C/WINDOWS/plAns.txt.RCM.xml");
        let body = std::fs::read_to_string(&sc).unwrap();
        assert!(body.contains("<name>plAns.txt</name>"));
        assert!(body.contains("<dirname>C:\\WINDOWS</dirname>"));
        assert!(body.contains("<size>5</size>"));
        assert!(body.contains("<accessedtime>NONE</accessedtime>"));
        assert!(!body.contains("<group>"));

        // Duplicate download -> REQ-3.4.3 suffix, sidecar mirrors it.
        let rel2 = pm
            .store_collected("C:\\WINDOWS\\plAns.txt", b"again", &meta)
            .unwrap();
        assert_eq!(rel2, "downloads/C/WINDOWS/plAns.txt.1");
        assert!(pm
            .root()
            .join("downloads.metadata/C/WINDOWS/plAns.txt.1.RCM.xml")
            .exists());
    }

    #[test]
    fn chunk_flow_part_state_finalize() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();

        assert!(!pm
            .store_collected_chunk("/etc/big.bin", 0, 3, b"AAA", "t-flow", &meta)
            .unwrap());
        let part = pm.root().join("downloads/etc/big.bin.part");
        let state = pm.root().join("downloads/etc/big.bin.part.state");
        assert!(part.exists());
        // 4-field state: next_idx,total_chunks,part_len,transfer_id.
        assert_eq!(std::fs::read_to_string(&state).unwrap(), "1,3,3,t-flow");

        // Out-of-order chunk rejected, .part kept.
        assert!(pm
            .store_collected_chunk("/etc/big.bin", 2, 3, b"CCC", "t-flow", &meta)
            .is_err());
        assert_eq!(std::fs::read(&part).unwrap(), b"AAA");

        assert!(!pm
            .store_collected_chunk("/etc/big.bin", 1, 3, b"BBB", "t-flow", &meta)
            .unwrap());
        assert!(pm
            .store_collected_chunk("/etc/big.bin", 2, 3, b"CCC", "t-flow", &meta)
            .unwrap());
        assert!(!part.exists());
        assert!(!state.exists());
        assert_eq!(
            std::fs::read(pm.root().join("downloads/etc/big.bin")).unwrap(),
            b"AAABBBCCC"
        );
        assert!(pm
            .root()
            .join("downloads.metadata/etc/big.bin.RCM.xml")
            .exists());

        // Re-collection while a stale final name exists -> counter suffix.
        assert!(pm
            .store_collected_chunk("/etc/big.bin", 0, 1, b"Z", "t-flow2", &meta)
            .unwrap());
        assert!(pm.root().join("downloads/etc/big.bin.1").exists());
        assert!(pm
            .root()
            .join("downloads.metadata/etc/big.bin.1.RCM.xml")
            .exists());
    }

    #[test]
    fn screenshot_and_keylog_naming() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let shot = ScreenshotMeta {
            captured_at: chrono::DateTime::parse_from_rfc3339("2026-01-06T09:21:33Z")
                .unwrap()
                .with_timezone(&Utc),
            toolspecific: "monitor0".into(),
            ext: "png".into(),
            originalsize: Some("680x320".into()),
            isfullscreen: Some(false),
            isminimized: Some(false),
            activewindow: Some(true),
            pid: Some("1364".into()),
            imagename: None,
            windowtitle: Some("Calculator".into()),
            session: None,
            user: Some("USER-PC\\Administrator".into()),
            monitor: Some("1".into()),
        };
        let rel = pm.store_screenshot(b"\x89PNG", &shot).unwrap();
        assert_eq!(rel, "output/screenshots/screenshot.20260106-092133.monitor0.png");
        let sc = std::fs::read_to_string(
            pm.root().join(&format!("{}.RCM.xml", rel)),
        )
        .unwrap();
        assert!(sc.contains("<screenshot version=\"1\">"));
        assert!(sc.contains("<isfullscreen>False</isfullscreen>"));
        assert!(sc.contains("<activewindow>True</activewindow>"));
        assert!(sc.contains("<imagename>NONE</imagename>"));
        assert!(sc.contains("<timestamp>2026-01-06T09:21:33.0000000Z</timestamp>"));

        // Same second + same toolspecific -> REQ-3.4.1 counter.
        let shot2 = ScreenshotMeta { ..shot };
        let rel2 = pm.store_screenshot(b"\x89PNG", &shot2).unwrap();
        assert_eq!(
            rel2,
            "output/screenshots/screenshot.20260106-092133.monitor0.0.png"
        );

        let caps = vec![KeyCapture {
            starttime: "2026-01-24T09:15:00.0000000Z".into(),
            endtime: Some("2026-01-24T09:16:12.0000000Z".into()),
            user: Some("USER-PC\\Administrator".into()),
            events: vec![KeyEvent {
                time: "2026-01-24T09:15:02.0000000Z".into(),
                pid: Some("1364".into()),
                imagename: Some("notepad.exe".into()),
                windowtitle: Some("Untitled - Notepad".into()),
                keys: "Hello world[ENTER]".into(),
            }],
        }];
        let krel = pm.store_keylog(&caps).unwrap();
        assert_eq!(krel, "output/keylogger/keylog.RCM.0.xml");
        let kdoc = std::fs::read_to_string(pm.root().join(&krel)).unwrap();
        assert!(kdoc.contains("<keylog version=\"1\">"));
        assert!(kdoc.contains("<keys>Hello world[ENTER]</keys>"));
        let krel2 = pm.store_keylog(&caps).unwrap();
        assert_eq!(krel2, "output/keylogger/keylog.RCM.1.xml");
    }

    #[test]
    fn seal_generations_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        pm.store_collected("C:\\a.txt", b"1", &CollectedMeta::default())
            .unwrap();
        assert!(!pm.is_sealed());
        let m0 = pm.seal().unwrap();
        assert_eq!(m0.file_name().unwrap(), "manifest.RCM.xml");
        assert!(pm.is_sealed());
        assert_eq!(pm.verify().unwrap(), Vec::<String>::new());
        // PACKAGE custody event recorded.
        let custody_doc =
            std::fs::read_to_string(pm.root().join("custody.RCM.xml")).unwrap();
        assert!(custody_doc.contains("<action>PACKAGE</action>"));

        // Post-seal modification + reseal -> generation 1.
        pm.store_collected("C:\\b.txt", b"2", &CollectedMeta::default())
            .unwrap();
        let m1 = pm.seal().unwrap();
        assert_eq!(m1.file_name().unwrap(), "manifest.RCM.1.xml");
        assert!(m0.exists());
        assert_eq!(pm.verify().unwrap(), Vec::<String>::new());
        // Manifest excludes itself, custody and in-flight artifacts.
        let body = std::fs::read_to_string(&m1).unwrap();
        assert!(!body.contains("custody"));
        assert!(!body.contains("manifest.RCM"));
    }

    #[test]
    fn create_or_open_concurrent_single_folder() {
        // Ported reproducer: 8 threads racing
        // create_or_open for the SAME (hostname, instance) must yield
        // exactly ONE package folder.
        let dir = tempfile::tempdir().unwrap();
        let base = Arc::new(dir.path().to_path_buf());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let b = base.clone();
            handles.push(std::thread::spawn(move || {
                PackageManager::create_or_open(&b, "RACE-HOST", "inst-race").unwrap()
            }));
        }
        let mut roots = Vec::new();
        for h in handles {
            roots.push(h.join().unwrap().root().to_path_buf());
        }
        let uniq: std::collections::HashSet<_> = roots.iter().collect();
        assert_eq!(uniq.len(), 1, "more than one root folder: {:?}", uniq);
        let n = std::fs::read_dir(base.as_path()).unwrap().count();
        assert_eq!(n, 1, "expected exactly one package folder, found {}", n);
    }

    #[test]
    fn chunk0_never_touches_committed_part_evidence() {
        // A collected file legitimately named "X.part" carries a sidecar:
        // it is committed evidence, not an in-flight transfer. A chunk-0
        // for "X" must NOT delete/overwrite it - the transfer claims the
        // NEXT free slot instead and completes normally.
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();
        let rel = pm
            .store_collected("C:\\data.part", b"EVIDENCE", &meta)
            .unwrap();
        assert_eq!(rel, "downloads/C/data.part");
        assert!(!pm
            .store_collected_chunk("C:\\data", 0, 2, b"chunk0", "t-ev", &meta)
            .unwrap());
        // The transfer took the next slot, leaving the evidence in place.
        assert_eq!(
            std::fs::read(pm.root().join("downloads/C/data.part")).unwrap(),
            b"EVIDENCE"
        );
        assert!(pm
            .root()
            .join("downloads.metadata/C/data.part.RCM.xml")
            .exists());
        assert!(!pm.root().join("downloads/C/data.part.state").exists());
        assert!(pm.root().join("downloads/C/data.part.1").exists());
        assert!(pm.root().join("downloads/C/data.part.1.state").exists());
        // Finalize: the new transfer lands at the plain final name.
        assert!(pm
            .store_collected_chunk("C:\\data", 1, 2, b"chunk1", "t-ev", &meta)
            .unwrap());
        assert_eq!(
            std::fs::read(pm.root().join("downloads/C/data")).unwrap(),
            b"chunk0chunk1"
        );
        assert_eq!(
            std::fs::read(pm.root().join("downloads/C/data.part")).unwrap(),
            b"EVIDENCE"
        );
        assert!(!pm.root().join("downloads/C/data.part.1").exists());
        assert!(!pm.root().join("downloads/C/data.part.1.state").exists());

        // Same story when the evidence was collected in a subdirectory.
        let rel2 = pm
            .store_collected("C:\\d\\log.part", b"EV2", &meta)
            .unwrap();
        assert_eq!(rel2, "downloads/C/d/log.part");
        assert!(pm
            .store_collected_chunk("C:\\d\\log", 0, 1, b"x", "t-ev2", &meta)
            .unwrap());
        assert_eq!(
            std::fs::read(pm.root().join("downloads/C/d/log.part")).unwrap(),
            b"EV2"
        );
        assert_eq!(
            std::fs::read(pm.root().join("downloads/C/d/log")).unwrap(),
            b"x"
        );
    }

    #[test]
    fn chunk0_restart_totals_and_state_rules() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();

        // In-flight transfer, then chunk-0 restart with the SAME id but a
        // DIFFERENT total: error, in-flight .part untouched.
        assert!(!pm.store_collected_chunk("/x/f", 0, 5, b"AA", "t-x", &meta).unwrap());
        let r = pm.store_collected_chunk("/x/f", 0, 2, b"BB", "t-x", &meta);
        assert!(r.is_err(), "restart with different total accepted: {:?}", r);
        assert_eq!(std::fs::read(pm.root().join("downloads/x/f.part")).unwrap(), b"AA");
        assert_eq!(
            std::fs::read_to_string(pm.root().join("downloads/x/f.part.state")).unwrap(),
            "1,5,2,t-x"
        );

        // Same-id same-total restart: truncates and retries cleanly.
        assert!(!pm.store_collected_chunk("/x/f", 0, 5, b"ZZ", "t-x", &meta).unwrap());
        assert_eq!(std::fs::read(pm.root().join("downloads/x/f.part")).unwrap(), b"ZZ");
        assert_eq!(
            std::fs::read_to_string(pm.root().join("downloads/x/f.part.state")).unwrap(),
            "1,5,2,t-x"
        );

        // Corrupt (legacy 2-field or garbage) state with existing .part:
        // the slot is committed evidence - never touched; the transfer
        // claims the next slot instead.
        std::fs::write(pm.root().join("downloads/x/f.part.state"), "1,5").unwrap();
        assert!(!pm
            .store_collected_chunk("/x/f", 0, 5, b"QQ", "t-x2", &meta)
            .unwrap());
        assert_eq!(std::fs::read(pm.root().join("downloads/x/f.part")).unwrap(), b"ZZ");
        assert_eq!(
            std::fs::read_to_string(pm.root().join("downloads/x/f.part.state")).unwrap(),
            "1,5"
        );
        assert_eq!(
            std::fs::read(pm.root().join("downloads/x/f.part.1")).unwrap(),
            b"QQ"
        );
    }

    #[test]
    fn chunk_state_strict_four_fields_and_replay_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();

        // Garbage state files - including the LEGACY 3-field form and 2/5
        // field counts - never match a transfer id, so chunk > 0 errors.
        for garbage in [
            "", "abc", "1", "1,2", "1,2,3", "1,2,3,4,5", "-1,2,3,t",
            "18446744073709551616,2,0,t", "1;2;3", "1,2,3,4",
        ] {
            let d = pm.root().join("downloads/g");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("f.part"), b"PRE").unwrap();
            std::fs::write(d.join("f.part.state"), garbage).unwrap();
            let r = pm.store_collected_chunk("/g/f", 1, 2, b"NEW", "t-g", &meta);
            assert!(r.is_err(), "garbage state {:?} was accepted", garbage);
            assert_eq!(std::fs::read(d.join("f.part")).unwrap(), b"PRE");
        }

        // Crash between append and state write: .part is LONGER than the
        // recorded len -> truncate to the recorded len and replay.
        assert!(!pm.store_collected_chunk("/h/big", 0, 3, b"AAAA", "t-h", &meta).unwrap());
        // Simulate the crashed append of chunk 1 (state still says next=1,len=4).
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(pm.root().join("downloads/h/big.part"))
                .unwrap();
            f.write_all(b"BBBB").unwrap();
        }
        // Replay of chunk 1 (possibly with different bytes): truncation
        // makes it idempotent.
        assert!(!pm.store_collected_chunk("/h/big", 1, 3, b"CC", "t-h", &meta).unwrap());
        assert_eq!(
            std::fs::read(pm.root().join("downloads/h/big.part")).unwrap(),
            b"AAAACC"
        );
        assert_eq!(
            std::fs::read_to_string(pm.root().join("downloads/h/big.part.state")).unwrap(),
            "2,3,6,t-h"
        );

        // .part SHORTER than the recorded len -> corruption, refuse.
        std::fs::write(pm.root().join("downloads/h/big.part"), b"A").unwrap();
        let r = pm.store_collected_chunk("/h/big", 2, 3, b"DD", "t-h", &meta);
        assert!(r.is_err(), "short .part accepted: {:?}", r);
    }

    #[test]
    fn sidecar_failure_leaves_no_orphan_data_file() {
        // 255-byte final component: the data file fits NAME_MAX but the
        // sidecar name (+".RCM.xml" = 263 bytes) does not -> the store must
        // fail AND remove the already-written data file (REQ-16.2).
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();
        let name = "n".repeat(255);
        let p = format!("C:\\d\\{}", name);
        let r = pm.store_collected(&p, b"x", &meta);
        assert!(r.is_err(), "255-byte component with oversized sidecar should fail");
        let data_dir = pm.root().join("downloads/C/d");
        let leftover: Vec<_> = std::fs::read_dir(&data_dir)
            .map(|rd| rd.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(leftover.is_empty(), "orphan data files: {:?}", leftover);
    }

    #[test]
    fn reject_filename_less_collected_paths_no_poisoning() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();
        for bad in [
            "C:", "C:\\", "C:/", "/", "\\\\", "//", "\\\\server\\share",
            "C:\\a\\", "", "  ", "..",
        ] {
            let r = pm.store_collected(bad, b"x", &meta);
            assert!(r.is_err(), "path {:?} should be rejected, got {:?}", bad, r);
        }
        // Rejection leaves no artifacts (in particular NO file named "C"
        // that would poison the downloads/C directory).
        let mut files = Vec::new();
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        walk(&pm.root().join("downloads"), &mut files);
        assert!(files.is_empty(), "rejected paths left artifacts: {:?}", files);
        // And the legitimate follow-up store still works.
        let rel = pm.store_collected("C:\\a.txt", b"y", &meta).unwrap();
        assert_eq!(rel, "downloads/C/a.txt");
        // Bare relative names stay legal.
        let rel2 = pm.store_collected("file.txt", b"z", &meta).unwrap();
        assert_eq!(rel2, "downloads/file.txt");
    }

    #[test]
    fn meta_cache_capped_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        for i in 0..5000u64 {
            pm.note_file_meta(
                "batch",
                &format!("rel/{}.txt", i),
                &format!("C:\\abs\\{}.txt", i),
                CollectedMeta::default(),
            );
        }
        assert!(pm.meta_cache_len() <= meta_cache_cap());
        assert_eq!(pm.meta_cache_len(), meta_cache_cap());
        // FIFO: the oldest announcements were evicted, the newest survive.
        assert!(pm.peek_file_meta("batch", "rel/0.txt").is_none());
        assert!(pm
            .peek_file_meta("batch", &format!("rel/{}.txt", 5000 - meta_cache_cap() - 1))
            .is_none());
        assert!(pm
            .peek_file_meta("batch", &format!("rel/{}.txt", 5000 - meta_cache_cap()))
            .is_some());
        assert!(pm.peek_file_meta("batch", "rel/4999.txt").is_some());
        // The eviction burst was logged once (component "agent", WARN).
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let log = std::fs::read_to_string(
            pm.root()
                .join("logs/rcm-server/agent")
                .join(&date)
                .join("0000.log"),
        )
        .unwrap();
        assert!(log.contains(" WARN "));
        assert!(log.contains("meta cache full"));
        assert_eq!(log.matches("meta cache full").count(), 1);
    }

    #[test]
    fn keylog_timestamps_validated() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let caps = vec![KeyCapture {
            starttime: "not-a-timestamp".into(),
            endtime: Some(
                "2026-01-24T09:16:12.0000000Z</timestamp><injected>pwn</injected><timestamp>"
                    .into(),
            ),
            user: None,
            events: vec![],
        }];
        let rel = pm.store_keylog(&caps).unwrap();
        let doc = std::fs::read_to_string(pm.root().join(&rel)).unwrap();
        assert!(!doc.contains("<injected>"), "timestamp injection: {}", doc);
        // Invalid endtime falls back to NONE; invalid starttime to now.
        assert!(doc.contains("<endtime>NONE</endtime>"));
        let re = regex::Regex::new(
            r"<starttime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z</starttime>",
        )
        .unwrap();
        assert!(re.is_match(&doc), "starttime fallback: {}", doc);
        // Envelope timestamp untouched by the injection.
        assert_eq!(doc.matches("<timestamp>").count(), 1);
    }

    #[test]
    fn meta_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "h", "i").unwrap();
        assert!(pm.take_file_meta("-", "a.txt").is_none());
        pm.note_file_meta("-", "a.txt", "C:\\a.txt", CollectedMeta::default());
        let (abs, _m) = pm.take_file_meta("-", "a.txt").unwrap();
        assert_eq!(abs, "C:\\a.txt");
        assert!(pm.take_file_meta("-", "a.txt").is_none());
    }

    #[test]
    fn meta_cache_take_keeps_order_bounded() {
        // note+take cycles must not leak `order` entries (a taken key is
        // removed from both map and order; the >2*CAP compaction is the
        // safety net).
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "h", "i").unwrap();
        for i in 0..5000u64 {
            let rel = format!("rel/{}.txt", i);
            pm.note_file_meta("batch", &rel, "C:\\abs", CollectedMeta::default());
            assert!(pm.take_file_meta("batch", &rel).is_some());
        }
        assert_eq!(pm.meta_cache_len(), 0, "taken entries linger in map");
        assert!(
            pm.meta_cache_order_len() <= 2 * meta_cache_cap(),
            "order leaked: {} entries after 5000 note+take cycles",
            pm.meta_cache_order_len()
        );
        // 5000 notes with NO take: FIFO stays exact at the cap boundary.
        for i in 0..5000u64 {
            pm.note_file_meta("batch", &format!("n/{}.txt", i), "C:\\abs", CollectedMeta::default());
        }
        assert_eq!(pm.meta_cache_len(), meta_cache_cap());
        assert!(pm.meta_cache_order_len() <= 2 * meta_cache_cap());
        assert!(pm
            .peek_file_meta("batch", &format!("n/{}.txt", 5000 - meta_cache_cap() - 1))
            .is_none());
        assert!(pm
            .peek_file_meta("batch", &format!("n/{}.txt", 5000 - meta_cache_cap()))
            .is_some());
        assert!(pm.peek_file_meta("batch", "n/4999.txt").is_some());
    }

    #[test]
    fn transfer_id_whitespace_rejected() {
        // Padded ids would be written into the state file verbatim but
        // parse_chunk_state trims the line - the id would never match
        // again and the slot would wedge. Reject up front.
        assert!(validate_transfer_id(" x").is_err());
        assert!(validate_transfer_id("x ").is_err());
        assert!(validate_transfer_id(" x ").is_err());
        assert!(validate_transfer_id("x").is_ok());
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();
        for bad in [" x", "x ", " x "] {
            let r = pm.store_collected_chunk("/w/f", 0, 1, b"z", bad, &meta);
            assert!(r.is_err(), "padded transfer id {:?} accepted", bad);
        }
        // A clean transfer over the same path still works (no wedge).
        assert!(pm
            .store_collected_chunk("/w/f", 0, 1, b"z", "t-ok", &meta)
            .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_marker_does_not_spin() {
        // A dangling symlink at the .rcmtarget path: reads return ENOENT
        // (folder judged empty) but create_new fails AlreadyExists
        // forever - the old code re-evaluated the SAME candidate in a
        // 100% CPU spin. It must move on to the next suffix.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        let folder = base.join("HOST-D");
        std::fs::create_dir(&folder).unwrap();
        std::os::unix::fs::symlink(base.join("no-such-target"), folder.join(".rcmtarget"))
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let pm = PackageManager::create_or_open(&base, "HOST-D", "inst-d").unwrap();
            tx.send(pm.root_name()).unwrap();
        });
        let name = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("create_or_open spun on a dangling symlink marker");
        assert_eq!(name, "HOST-D.1");
    }

    /// Backdate a file's mtime (atime too) by `secs_ago` seconds.
    #[cfg(unix)]
    fn backdate_mtime(path: &std::path::Path, secs_ago: i64) {
        use std::os::unix::ffi::OsStrExt;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let t = (now - secs_ago) as libc::time_t;
        let times = [
            libc::timespec {
                tv_sec: t,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: t,
                tv_nsec: 0,
            },
        ];
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat failed for {}", path.display());
    }

    #[test]
    fn reap_at_open_removes_abandoned_slots() {
        // Slot artifacts older than the staleness TTL found under
        // downloads/ at package open are reaped (WARN-logged); fresh
        // artifacts and sidecar-carrying evidence survive.
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let pm = PackageManager::create_or_open(base, "USER-PC", "i").unwrap();
        let root = pm.root().to_path_buf();
        let d = root.join("downloads/x");
        std::fs::create_dir_all(&d).unwrap();
        for name in ["f.part", "f.part.state", "f.part.3", "f.part.3.state"] {
            std::fs::write(d.join(name), b"stale").unwrap();
            // Older than the 24h TTL -> abandoned debris.
            backdate_mtime(&d.join(name), 25 * 60 * 60);
        }
        // Committed evidence named *.part WITH a sidecar is never reaped.
        std::fs::write(d.join("keep.part"), b"EVIDENCE").unwrap();
        backdate_mtime(&d.join("keep.part"), 25 * 60 * 60);
        let sc = root.join("downloads.metadata/x");
        std::fs::create_dir_all(&sc).unwrap();
        std::fs::write(sc.join("keep.part.RCM.xml"), b"sc").unwrap();
        drop(pm);

        let pm2 = PackageManager::create_or_open(base, "USER-PC", "i").unwrap();
        for name in ["f.part", "f.part.state", "f.part.3", "f.part.3.state"] {
            assert!(!d.join(name).exists(), "slot artifact not reaped: {}", name);
        }
        assert_eq!(std::fs::read(d.join("keep.part")).unwrap(), b"EVIDENCE");
        assert!(sc.join("keep.part.RCM.xml").exists());
        // Each reap was WARN-logged (component "agent").
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let log = std::fs::read_to_string(
            pm2.root()
                .join("logs/rcm-server/agent")
                .join(&date)
                .join("0000.log"),
        )
        .unwrap();
        assert!(log.contains(" WARN "));
        assert!(log.contains("reaped abandoned transfer slot artifact"));

        // open_by_root_name reaps too.
        for name in ["g.part.1", "g.part.1.state"] {
            std::fs::write(d.join(name), b"stale").unwrap();
            backdate_mtime(&d.join(name), 25 * 60 * 60);
        }
        let _pm3 = PackageManager::open_by_root_name(base, "USER-PC").unwrap();
        assert!(!d.join("g.part.1").exists());
        assert!(!d.join("g.part.1.state").exists());
    }

    // The at-open sweep must not kill a LIVE transfer owned
    // by another open manager - only artifacts older than the staleness
    // TTL are abandoned debris.
    #[test]
    fn second_open_preserves_live_inflight_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let m1 = PackageManager::create_or_open(base, "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();
        // m1 starts a FRESH in-flight transfer (chunk 0 of 2).
        assert!(!m1
            .store_collected_chunk("/x/big.bin", 0, 2, b"CHUNK0", "t-live", &meta)
            .unwrap());
        let part = m1.root().join("downloads/x/big.bin.part");
        let state = m1.root().join("downloads/x/big.bin.part.state");
        assert!(part.exists() && state.exists());

        // A second open of the same base+target must NOT reap m1's live
        // slot artifacts (fresh mtimes are within the TTL).
        let _m2 = PackageManager::create_or_open(base, "USER-PC", "i").unwrap();
        assert!(part.exists(), "live .part reaped by second open");
        assert!(state.exists(), "live .state reaped by second open");

        // m1's transfer is still completable: chunk 1 finalizes it.
        assert!(m1
            .store_collected_chunk("/x/big.bin", 1, 2, b"CHUNK1", "t-live", &meta)
            .unwrap());
        assert_eq!(
            std::fs::read(m1.root().join("downloads/x/big.bin")).unwrap(),
            b"CHUNK0CHUNK1"
        );
    }

    #[test]
    fn reap_at_open_ttl_rules() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let pm = PackageManager::create_or_open(base, "USER-PC", "i").unwrap();
        let root = pm.root().to_path_buf();
        let d = root.join("downloads/x");
        std::fs::create_dir_all(&d).unwrap();

        // (b) Backdated (>TTL) pair: reaped at open.
        std::fs::write(d.join("old.part"), b"OLD").unwrap();
        std::fs::write(d.join("old.part.state"), b"1,2,3,t-old").unwrap();
        backdate_mtime(&d.join("old.part"), 25 * 60 * 60);
        backdate_mtime(&d.join("old.part.state"), 25 * 60 * 60);

        // Fresh pair: live transfer - both survive (state is fresh even
        // though the part looks old; the state's mtime rules the pair).
        std::fs::write(d.join("live.part"), b"LIVE").unwrap();
        std::fs::write(d.join("live.part.state"), b"1,2,4,t-live").unwrap();
        backdate_mtime(&d.join("live.part"), 25 * 60 * 60);

        // (c) Orphan .part without state: backdated -> reaped; fresh ->
        // kept.
        std::fs::write(d.join("orphan-old.part.2"), b"OLD").unwrap();
        backdate_mtime(&d.join("orphan-old.part.2"), 25 * 60 * 60);
        std::fs::write(d.join("orphan-fresh.part.2"), b"FRESH").unwrap();
        drop(pm);

        let _pm2 = PackageManager::create_or_open(base, "USER-PC", "i").unwrap();
        assert!(!d.join("old.part").exists(), "stale pair part kept");
        assert!(!d.join("old.part.state").exists(), "stale pair state kept");
        assert!(d.join("live.part").exists(), "live pair part reaped");
        assert!(d.join("live.part.state").exists(), "live pair state reaped");
        assert!(!d.join("orphan-old.part.2").exists(), "stale orphan kept");
        assert!(d.join("orphan-fresh.part.2").exists(), "fresh orphan reaped");
    }

    #[test]
    fn stale_slots_reaped_at_chunk_zero() {
        // Fill ALL 8 slots with abandoned transfers (parseable states,
        // foreign ids). Fresh states still block a new transfer; once the
        // TTL classifies them as stale, chunk-0 reaps them and the new
        // transfer succeeds instead of dying with "too many concurrent
        // transfers" forever.
        let dir = tempfile::tempdir().unwrap();
        let pm = PackageManager::create_or_open(dir.path(), "USER-PC", "i").unwrap();
        let meta = CollectedMeta::default();
        let d = pm.root().join("downloads/x");
        std::fs::create_dir_all(&d).unwrap();
        for slot in 0..max_chunk_slots() {
            let (sp, ss) = chunk_slot_paths(&d.join("f"), slot);
            std::fs::write(&sp, b"OLD").unwrap();
            std::fs::write(&ss, format!("1,2,3,other-{}", slot)).unwrap();
        }
        // Fresh foreign slots block: live transfers own every slot.
        let r = pm.store_collected_chunk("/x/f", 0, 1, b"NEW", "t-new", &meta);
        assert!(r.is_err(), "fresh foreign slots did not block: {:?}", r);

        // Shrink the TTL hermetically (test-only knob) so the states are
        // stale, then retry: all 8 slots are reaped and the transfer
        // completes.
        pm.set_stale_slot_ttl(std::time::Duration::from_secs(0));
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(pm
            .store_collected_chunk("/x/f", 0, 1, b"NEW", "t-new", &meta)
            .unwrap());
        assert_eq!(
            std::fs::read(pm.root().join("downloads/x/f")).unwrap(),
            b"NEW"
        );
        for slot in 0..max_chunk_slots() {
            let (sp, ss) = chunk_slot_paths(&d.join("f"), slot);
            assert!(!sp.exists(), "stale slot {} part not reaped", slot);
            assert!(!ss.exists(), "stale slot {} state not reaped", slot);
        }
        // Reaps were WARN-logged (component "agent").
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let log = std::fs::read_to_string(
            pm.root()
                .join("logs/rcm-server/agent")
                .join(&date)
                .join("0000.log"),
        )
        .unwrap();
        assert!(log.contains("reaped stale transfer slot"));
    }
}