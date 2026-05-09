//! Event sink abstraction. Phase 1 ships only `JsonlSink`.

pub mod jsonl;

use crate::event::Event;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

pub trait EventSink {
    /// Write one event. Implementations are responsible for any rotation/fsync logic.
    fn write(&mut self, event: &Event) -> Result<(), SinkError>;

    /// Force durable persistence of all pending events.
    fn flush_durable(&mut self) -> Result<(), SinkError>;

    /// Cleanly close the sink.
    fn shutdown(&mut self) -> Result<(), SinkError>;
}
