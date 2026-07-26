// ./src/rcm/registry.rs
// Server-wide registry of open packages, keyed by stable target identity.
// The global instance uses base dir "downloads" (the existing storage
// root, kept so current API/panel walkers keep working).
//
// A root-name secondary index guarantees ONE PackageManager (one write
// Mutex) per on-disk package no matter which lookup path got there first -
// otherwise for_target and by_root_name could hand out independent
// instances and silently defeat the write serialization of Section 6.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;

use super::package::{PackageManager, RcmError};

pub struct PackageRegistry {
    base: PathBuf,
    map: DashMap<String, Arc<PackageManager>>,
    // root folder name -> key in `map`
    root_index: DashMap<String, String>,
    // Serializes the WHOLE get-or-create-and-index sequence (create_or_open
    // + root_index/map updates) so two threads can never allocate divergent
    // managers or folders for the same target concurrently.
    create_lock: Mutex<()>,
}

/// Global registry (server-wide). base = "downloads".
///
/// NOTE: config.rcm.storage_base currently defaults to "data", which does
/// NOT match this long-standing storage root. Wiring it through would
/// silently relocate existing packages, so the base stays "downloads" until
/// the config default is corrected; see the config-migration report.
pub fn registry() -> &'static PackageRegistry {
    static REG: OnceLock<PackageRegistry> = OnceLock::new();
    REG.get_or_init(|| PackageRegistry::new(PathBuf::from(crate::config::config().rcm.storage_base.as_str())))
}

impl PackageRegistry {
    /// Registry over an explicit base dir (tests use a tempdir; production
    /// uses the global [`registry()`]).
    pub fn new(base: PathBuf) -> Self {
        PackageRegistry {
            base,
            map: DashMap::new(),
            root_index: DashMap::new(),
            create_lock: Mutex::new(()),
        }
    }

    /// Lock the registry mutex, recovering from poisoning (the maps stay
    /// consistent across panics; a poisoned lock must not cascade).
    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.create_lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    fn get_by_root(&self, root_name: &str) -> Option<Arc<PackageManager>> {
        let key = self.root_index.get(root_name)?.clone();
        self.map.get(&key).map(|p| p.clone())
    }

    /// key = computer_id if non-empty, else hostname, else "unknown-target".
    /// The (unprefixed) key doubles as the instance id written into
    /// .rcmtarget, so the same target always reopens the same root folder
    /// (REQ-3.1). In the map the key is namespaced as "cid:<key>" so a
    /// hostile computer_id like "root:HOST-A" can never collide with a
    /// by_root_name cache entry.
    pub fn for_target(
        &self,
        hostname: &str,
        computer_id: &str,
    ) -> Result<Arc<PackageManager>, RcmError> {
        let instance_key = if !computer_id.is_empty() {
            computer_id.to_string()
        } else if !hostname.is_empty() {
            hostname.to_string()
        } else {
            "unknown-target".to_string()
        };
        let key = format!("cid:{}", instance_key);
        // Held across the whole get-or-create-and-index sequence.
        let _g = self.lock();
        if let Some(p) = self.map.get(&key) {
            return Ok(p.clone());
        }
        let pm = PackageManager::create_or_open(&self.base, hostname, &instance_key)?;
        // Another lookup path may already manage this root folder.
        if let Some(existing) = self.get_by_root(&pm.root_name()) {
            return Ok(existing);
        }
        self.root_index.insert(pm.root_name(), key.clone());
        Ok(self.map.entry(key).or_insert(pm).value().clone())
    }

    /// Open (and cache) a package by its root folder name, e.g. for API
    /// routes after a server restart.
    pub fn by_root_name(&self, root_name: &str) -> Result<Arc<PackageManager>, RcmError> {
        // Held across the whole get-or-open-and-index sequence.
        let _g = self.lock();
        if let Some(p) = self.get_by_root(root_name) {
            return Ok(p);
        }
        let pm = PackageManager::open_by_root_name(&self.base, root_name)?;
        let key = format!("root:{}", root_name);
        self.root_index.insert(root_name.to_string(), key.clone());
        Ok(self.map.entry(key).or_insert(pm).value().clone())
    }

    pub fn list(&self) -> Vec<Arc<PackageManager>> {
        self.map.iter().map(|r| r.value().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_precedence_and_caching() {
        let dir = tempfile::tempdir().unwrap();
        let reg = PackageRegistry::new(dir.path().to_path_buf());

        // computer_id wins over hostname.
        let a = reg.for_target("HOST-A", "cid-1").unwrap();
        let b = reg.for_target("HOST-B", "cid-1").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.root_name(), "HOST-A");

        // No computer_id -> hostname key.
        let c = reg.for_target("HOST-C", "").unwrap();
        assert_eq!(c.root_name(), "HOST-C");

        // Neither -> unknown-target (shared).
        let d = reg.for_target("", "").unwrap();
        assert_eq!(d.root_name(), "unknown-target");
        let e = reg.for_target("", "").unwrap();
        assert!(Arc::ptr_eq(&d, &e));

        // by_root_name after for_target returns the SAME instance (one
        // write Mutex per package).
        let f = reg.by_root_name("HOST-A").unwrap();
        assert!(Arc::ptr_eq(&a, &f));

        // And the reverse direction: by_root_name first, then for_target.
        let g = reg.by_root_name("HOST-C").unwrap();
        assert!(Arc::ptr_eq(&c, &g));

        // Genuine reverse: package on disk that this registry has only
        // seen via by_root_name; a later for_target must unify with it.
        let pm = PackageManager::create_or_open(dir.path(), "HOST-R", "cid-r").unwrap();
        drop(pm);
        let h = reg.by_root_name("HOST-R").unwrap();
        let i = reg.for_target("HOST-R", "cid-r").unwrap();
        assert!(Arc::ptr_eq(&h, &i));

        assert_eq!(reg.list().len(), 4);
    }

    #[test]
    fn cid_namespace_prevents_root_key_spoofing() {
        // A hostile computer_id shaped like a by_root_name map key must NOT
        // hit the "root:<name>" cache entry.
        let dir = tempfile::tempdir().unwrap();
        let reg = PackageRegistry::new(dir.path().to_path_buf());
        let a = reg.for_target("HOST-A", "cid-a").unwrap();
        let spoof = reg.for_target("WHATEVER", "root:HOST-A").unwrap();
        assert!(
            !Arc::ptr_eq(&a, &spoof),
            "hostile computer_id collided with a by_root_name cache entry"
        );
        assert_eq!(spoof.root_name(), "WHATEVER");
        // The instance id written on disk stays the RAW key (unprefixed).
        let spoof2 = reg.for_target("WHATEVER", "root:HOST-A").unwrap();
        assert!(Arc::ptr_eq(&spoof, &spoof2), "same target must unify");
    }

    #[test]
    fn concurrent_for_target_one_folder() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Arc::new(PackageRegistry::new(dir.path().to_path_buf()));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let r = reg.clone();
            handles.push(std::thread::spawn(move || {
                r.for_target("RACE-HOST", "cid-race").unwrap()
            }));
        }
        let mut pms = Vec::new();
        for h in handles {
            pms.push(h.join().unwrap());
        }
        for p in &pms[1..] {
            assert!(Arc::ptr_eq(&pms[0], p), "divergent managers handed out");
        }
        let n = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(n, 1, "target split into {} folders", n);
    }
}