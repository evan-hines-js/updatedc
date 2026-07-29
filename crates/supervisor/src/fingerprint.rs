use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use updated_contracts::telemetry::Fingerprint;

use crate::update::FingerprintJob;

/// Fingerprints are intentionally much less frequent than health checks. This is agent policy,
/// not application configuration: providers implement what is measured, while the agent owns
/// when measurement is safe and how its process lifetime is bounded.
pub(crate) const INTERVAL: Duration = Duration::from_secs(60 * 60);
const JITTER_PERCENT: u32 = 10;

struct Worker {
    cancelled: Arc<AtomicBool>,
    handle: JoinHandle<io::Result<Fingerprint>>,
}

/// Sole owner of fingerprint scheduling, execution, cancellation, and the publishable result.
/// A fingerprint hook never overlaps a deployment hook: the deployment path calls `restart_after`
/// and waits for this worker's contained process tree to die before beginning its transaction.
pub(crate) struct Tracker {
    current: Option<Fingerprint>,
    due: Instant,
    worker: Option<Worker>,
}

impl Tracker {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            current: None,
            due: now,
            worker: None,
        }
    }

    pub(crate) fn current(&self) -> Option<&Fingerprint> {
        self.current.as_ref()
    }

    fn start_worker(
        &mut self,
        run: impl FnOnce(&AtomicBool) -> io::Result<Fingerprint> + Send + 'static,
    ) {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        self.worker = Some(Worker {
            cancelled,
            handle: thread::spawn(move || run(&worker_cancelled)),
        });
    }

    /// Cancel and reap any observation of the old deployment. The next healthy probe starts a
    /// fresh measurement of the deployment that won the transaction (including rollback).
    pub(crate) fn restart_after_deployment(&mut self, now: Instant) {
        if let Some(worker) = self.worker.take() {
            worker.cancelled.store(true, Ordering::Release);
            let _ = worker.handle.join();
        }
        self.current = None;
        self.due = now;
    }

    /// Reap a completed observation and, when due, start at most one new worker. Preparation is
    /// kept on the supervisor thread so invalid signed/provider state fails before spawning.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        healthy: bool,
        node: &str,
        prepare: impl FnOnce() -> io::Result<FingerprintJob>,
    ) -> Option<io::Result<()>> {
        let mut completed = None;
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.handle.is_finished())
        {
            let worker = self.worker.take().expect("finished worker exists");
            let result = worker
                .handle
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("fingerprint worker panicked")));
            self.current = result.as_ref().ok().cloned();
            self.due = now + crate::schedule::jitter_for_key(INTERVAL, JITTER_PERCENT, node);
            completed = Some(result.map(|_| ()))
        }

        if self.worker.is_none() && now >= self.due {
            if !healthy {
                self.current = None;
                return completed;
            }
            match prepare() {
                Ok(job) => {
                    self.start_worker(move |cancelled| job.run(cancelled));
                }
                Err(error) => {
                    self.current = None;
                    self.due =
                        now + crate::schedule::jitter_for_key(INTERVAL, JITTER_PERCENT, node);
                    return Some(Err(error));
                }
            }
        }
        completed
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        self.restart_after_deployment(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn value(byte: char) -> Fingerprint {
        Fingerprint {
            definition_sha256: byte.to_string().repeat(64),
            output_sha256: byte.to_ascii_uppercase().to_string().repeat(64),
        }
    }

    #[test]
    fn deployment_cancels_and_joins_the_old_observation_before_returning() {
        let start = Instant::now();
        let mut tracker = Tracker::new(start);
        tracker.current = Some(value('a'));
        let (started_tx, started_rx) = mpsc::channel();
        let (stopped_tx, stopped_rx) = mpsc::channel();
        tracker.start_worker(move |cancelled| {
            started_tx.send(()).unwrap();
            while !cancelled.load(Ordering::Acquire) {
                thread::yield_now();
            }
            stopped_tx.send(()).unwrap();
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        tracker.restart_after_deployment(start + Duration::from_secs(1));

        stopped_rx.try_recv().unwrap();
        assert!(tracker.worker.is_none());
        assert!(tracker.current().is_none());
        assert_eq!(tracker.due, start + Duration::from_secs(1));
    }

    #[test]
    fn completed_measurement_is_published_and_scheduled_about_an_hour_out() {
        let start = Instant::now();
        let mut tracker = Tracker::new(start);
        tracker.start_worker(|_| Ok(value('b')));
        while !tracker.worker.as_ref().unwrap().handle.is_finished() {
            thread::yield_now();
        }
        let now = start + Duration::from_secs(1);
        let result = tracker.poll(now, true, "node-a", || {
            panic!("a completed worker must advance the cadence before starting another")
        });
        assert!(result.unwrap().is_ok());
        assert_eq!(tracker.current(), Some(&value('b')));
        assert!(tracker.due >= now + Duration::from_secs(54 * 60));
        assert!(tracker.due <= now + Duration::from_secs(66 * 60));
    }
}
