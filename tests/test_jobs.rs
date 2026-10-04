// tests/test_jobs.rs - Job manager lifecycle tests

use rcm::agent::jobs::{JobManager, JobStatus};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_job_spawn_and_complete() {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    let job_id = mgr.spawn("test job".into(), 1, |sink| async move {
        sink.send_chunk("working...").await;
        ("done".into(), String::new(), 0)
    });

    assert_eq!(job_id, 1);

    let jobs = mgr.list();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, JobStatus::Running);
    assert_eq!(jobs[0].description, "test job");

    // Wait for completion
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Drain the output channel
    while rx.try_recv().is_ok() {}
}

#[tokio::test]
async fn test_job_ids_increment() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    let id1 = mgr.spawn("job1".into(), 1, |_| async { ("".into(), "".into(), 0) });
    let id2 = mgr.spawn("job2".into(), 2, |_| async { ("".into(), "".into(), 0) });
    let id3 = mgr.spawn("job3".into(), 3, |_| async { ("".into(), "".into(), 0) });

    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(id3, 3);
}

#[tokio::test]
async fn test_job_kill() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    let job_id = mgr.spawn("long job".into(), 1, |_sink| async {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        ("should not reach".into(), String::new(), 0)
    });

    let msg = mgr.kill(job_id);
    assert!(msg.contains("killed"));

    let jobs = mgr.list();
    assert_eq!(jobs[0].status, JobStatus::Killed);
}

#[tokio::test]
async fn test_job_kill_nonexistent() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    let msg = mgr.kill(999);
    assert!(msg.contains("not found"));
}

#[tokio::test]
async fn test_job_purge() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    mgr.spawn("j1".into(), 1, |_| async { ("".into(), "".into(), 0) });
    mgr.spawn("j2".into(), 2, |_| async { ("".into(), "".into(), 0) });

    // Kill one
    mgr.kill(1);

    let purged = mgr.purge_completed();
    assert_eq!(purged, 1); // Killed one was purged
}

#[tokio::test]
async fn test_shared_manager_marks_completed() {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let mgr = JobManager::new_shared(tx);

    let job_id = mgr.lock().unwrap().spawn("finishing job".into(), 1, |sink| async move {
        sink.send_chunk("chunk a").await;
        sink.send_chunk("chunk b").await;
        ("final output".into(), String::new(), 0)
    });

    // Give the job and its supervisor time to run to completion.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let guard = mgr.lock().unwrap();
    let jobs = guard.list();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, job_id);
    assert_eq!(jobs[0].status, JobStatus::Completed);
    assert!(jobs[0].finished_at.is_some());
    assert_eq!(jobs[0].chunks_sent, 2);
    drop(guard);

    // The supervisor still forwards JOB_FINAL upstream after bookkeeping.
    let mut saw_final = false;
    while let Ok(data) = rx.try_recv() {
        if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(out) = resp.get(1).and_then(|o| o.as_str()) {
                if out.starts_with("JOB_FINAL:") {
                    saw_final = true;
                }
            }
        }
    }
    assert!(saw_final, "supervisor must send JOB_FINAL after completion");
}

#[tokio::test]
async fn test_shared_manager_marks_failed() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mgr = JobManager::new_shared(tx);

    mgr.lock().unwrap().spawn("failing job".into(), 1, |_| async {
        (String::new(), "boom".into(), 1)
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let guard = mgr.lock().unwrap();
    let jobs = guard.list();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, JobStatus::Failed);
    assert!(jobs[0].finished_at.is_some());
}

#[tokio::test]
async fn test_supervisor_does_not_resurrect_killed_job() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mgr = JobManager::new_shared(tx);

    let job_id = mgr.lock().unwrap().spawn("long job".into(), 1, |_sink| async {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        ("should not reach".into(), String::new(), 0)
    });

    let msg = mgr.lock().unwrap().kill(job_id);
    assert!(msg.contains("killed"));

    // Wait long enough for the supervisor to observe the abort and report.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let guard = mgr.lock().unwrap();
    let jobs = guard.list();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, JobStatus::Killed);
}

#[tokio::test]
async fn test_purge_removes_naturally_finished_jobs() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mgr = JobManager::new_shared(tx);

    mgr.lock().unwrap().spawn("quick".into(), 1, |_| async {
        ("done".into(), String::new(), 0)
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let mut guard = mgr.lock().unwrap();
    let purged = guard.purge_completed();
    assert_eq!(purged, 1);
    assert!(guard.list().is_empty());
}

#[tokio::test]
async fn test_plain_manager_keeps_running_status() {
    // Managers built with new() (no self-reference) still stream and send
    // JOB_FINAL, but their local entries stay Running; only new_shared()
    // managers get completion callbacks.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    mgr.spawn("plain".into(), 1, |_| async { ("done".into(), String::new(), 0) });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let jobs = mgr.list();
    assert_eq!(jobs[0].status, JobStatus::Running);

    let mut saw_final = false;
    while let Ok(data) = rx.try_recv() {
        if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(out) = resp.get(1).and_then(|o| o.as_str()) {
                if out.starts_with("JOB_FINAL:") {
                    saw_final = true;
                }
            }
        }
    }
    assert!(saw_final, "plain manager supervisor still sends JOB_FINAL");
}

#[tokio::test]
async fn test_job_list_json() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    mgr.spawn("test".into(), 1, |_| async { ("".into(), "".into(), 0) });

    let json = mgr.list_json();

    // JobInfo serializes as a positional seq:
    // [id, description, status, started_at, finished_at, chunks_sent]
    // with JobStatus as a u8 tag (Running=0).
    let jobs: Vec<serde_json::Value> = serde_json::from_str(&json)
        .expect("list_json must return valid JSON");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0][0], 1);
    assert_eq!(jobs[0][1], "test");
    assert_eq!(jobs[0][2], 0); // JobStatus::Running
}

#[tokio::test]
async fn test_job_output_sink_sends_chunks() {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let mut mgr = JobManager::new(tx);

    mgr.spawn("chunked".into(), 42, |sink| async move {
        sink.send_chunk("line 1").await;
        sink.send_chunk("line 2").await;
        ("final".into(), String::new(), 0)
    });

    // Wait for chunks
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut chunks = vec![];
    while let Ok(data) = rx.try_recv() {
        if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&data) {
            // CommandResponse is a positional seq: [request_id, output,
            // error, exit_code] - output is element 1.
            if let Some(out) = resp.get(1).and_then(|o| o.as_str()) {
                chunks.push(out.to_string());
            }
        }
    }

    // Should have at least the stream chunks
    assert!(chunks.iter().any(|c| c.contains("JOB_STREAM")));
}