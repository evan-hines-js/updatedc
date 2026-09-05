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
/// A fingerprint hook never overlaps a mutation hook: deployment paths call `restart_after`, and
/// steady convergence calls `pause_for_mutation`; both wait for this worker's contained process
/// tree to die before `converge` begins.
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

    fn cancel_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancelled.store(true, Ordering::Release);
            let _ = worker.handle.join();
        }
    }

    /// Stop an observation before a `converge` can touch the state it reads. A successful no-change
    /// result may keep the last completed value and its hourly cadence; a changed result follows
    /// this with [`restart_after_deployment`](Self::restart_after_deployment).
    pub(crate) fn pause_for_mutation(&mut self) {
        self.cancel_worker();
    }

    /// Cancel and reap any observation of the old deployment. The next healthy probe starts a
    /// fresh measurement of the deployment that won the transaction (including rollback).
    pub(crate) fn restart_after_deployment(&mut self, now: Instant) {
        self.cancel_worker();
        self.current = None;
        self.due = now;
    }

    /// Reap a completed observation and, when due, start at most one new worker. Preparation is
    /// kept on the agent thread so invalid signed/provider state fails before spawning.
    ///
    /// Returns the failure of this poll, if any; a measurement that succeeded is published through
    /// [`current`](Self::current) and needs nothing from the caller. Whether a worker was reaped at
    /// all is not the caller's business, so it is not reported.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        healthy: bool,
        node: &str,
        prepare: impl FnOnce() -> io::Result<FingerprintJob>,
    ) -> Option<io::Error> {
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
            completed = result.err();
        }

        // A measurement that spans an unhealthy interval is not evidence of one stable state.
        // Cancel it immediately and require a fresh observation after readiness returns.
        if !healthy {
            self.cancel_worker();
            self.current = None;
            self.due = now;
            return completed;
        }

        if self.worker.is_none() && now >= self.due {
            match prepare() {
                Ok(job) => {
                    self.start_worker(move |cancelled| job.run(cancelled));
                }
                Err(error) => {
                    self.current = None;
                    self.due =
                        now + crate::schedule::jitter_for_key(INTERVAL, JITTER_PERCENT, node);
                    return Some(error);
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn value(byte: char) -> Fingerprint {
        Fingerprint {
            definition_sha256: byte.to_string().repeat(64),
            output_sha256: byte.to_string().repeat(64),
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
    fn a_no_change_mutation_pauses_observation_without_destroying_prior_evidence() {
        let start = Instant::now();
        let due = start + INTERVAL;
        let mut tracker = Tracker::new(start);
        tracker.current = Some(value('a'));
        tracker.due = due;
        let (started_tx, started_rx) = mpsc::channel();
        tracker.start_worker(move |cancelled| {
            started_tx.send(()).unwrap();
            while !cancelled.load(Ordering::Acquire) {
                thread::yield_now();
            }
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        tracker.pause_for_mutation();

        assert!(tracker.worker.is_none());
        assert_eq!(tracker.current(), Some(&value('a')));
        assert_eq!(tracker.due, due);
    }

    #[test]
    fn unhealthy_state_cancels_in_flight_measurement_and_requires_a_fresh_one() {
        let start = Instant::now();
        let mut tracker = Tracker::new(start);
        tracker.current = Some(value('a'));
        let (started_tx, started_rx) = mpsc::channel();
        tracker.start_worker(move |cancelled| {
            started_tx.send(()).unwrap();
            while !cancelled.load(Ordering::Acquire) {
                thread::yield_now();
            }
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let unhealthy_at = start + Duration::from_secs(1);

        assert!(tracker
            .poll(unhealthy_at, false, "node-a", || panic!("unhealthy"))
            .is_none());
        assert!(tracker.worker.is_none());
        assert!(tracker.current().is_none());
        assert_eq!(tracker.due, unhealthy_at);
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
        assert!(
            result.is_none(),
            "a measurement that succeeded reports no error"
        );
        assert_eq!(
            tracker.current(),
            Some(&value('b')),
            "the worker was reaped and its measurement published"
        );
        assert!(tracker.due >= now + Duration::from_secs(54 * 60));
        assert!(tracker.due <= now + Duration::from_secs(66 * 60));
    }
}
