//! LogEntry struct definition with Python bindings

use pyo3::prelude::*;
use std::collections::HashMap;

/// Standardized log entry structure
///
/// This struct mirrors the Python LogEntry dataclass for seamless interoperability.
/// All fields are optional to handle various log formats.
#[pyclass]
#[derive(Clone, Debug, Default)]
pub struct LogEntry {
    /// Timestamp string (various formats supported)
    #[pyo3(get, set)]
    pub timestamp: Option<String>,

    /// Source hostname
    #[pyo3(get, set)]
    pub hostname: Option<String>,

    /// Process/application name
    #[pyo3(get, set)]
    pub process: Option<String>,

    /// Process ID
    #[pyo3(get, set)]
    pub pid: Option<i32>,

    /// Log severity/level (ERROR, WARN, INFO, DEBUG, etc.)
    #[pyo3(get, set)]
    pub severity: Option<String>,

    /// Log message content
    #[pyo3(get, set)]
    pub message: String,

    /// Source IP address
    #[pyo3(get, set)]
    pub source_ip: Option<String>,

    /// Destination IP address
    #[pyo3(get, set)]
    pub dest_ip: Option<String>,

    /// Username associated with the log entry
    #[pyo3(get, set)]
    pub user: Option<String>,

    /// Event ID (for Windows Event Logs, etc.)
    #[pyo3(get, set)]
    pub event_id: Option<String>,

    /// Original raw log line
    #[pyo3(get, set)]
    pub raw: String,
}

#[pymethods]
impl LogEntry {
    /// Create a new LogEntry
    #[new]
    #[pyo3(signature = (
        timestamp = None,
        hostname = None,
        process = None,
        pid = None,
        severity = None,
        message = String::new(),
        source_ip = None,
        dest_ip = None,
        user = None,
        event_id = None,
        raw = String::new()
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        timestamp: Option<String>,
        hostname: Option<String>,
        process: Option<String>,
        pid: Option<i32>,
        severity: Option<String>,
        message: String,
        source_ip: Option<String>,
        dest_ip: Option<String>,
        user: Option<String>,
        event_id: Option<String>,
        raw: String,
    ) -> Self {
        LogEntry {
            timestamp,
            hostname,
            process,
            pid,
            severity,
            message,
            source_ip,
            dest_ip,
            user,
            event_id,
            raw,
        }
    }

    /// Convert to dictionary (matches Python LogEntry.to_dict())
    fn to_dict(&self) -> HashMap<String, Option<String>> {
        let mut map = HashMap::new();
        map.insert("timestamp".to_string(), self.timestamp.clone());
        map.insert("hostname".to_string(), self.hostname.clone());
        map.insert("process".to_string(), self.process.clone());
        map.insert("pid".to_string(), self.pid.map(|p| p.to_string()));
        map.insert("severity".to_string(), self.severity.clone());
        map.insert("message".to_string(), Some(self.message.clone()));
        map.insert("source_ip".to_string(), self.source_ip.clone());
        map.insert("dest_ip".to_string(), self.dest_ip.clone());
        map.insert("user".to_string(), self.user.clone());
        map.insert("event_id".to_string(), self.event_id.clone());
        map.insert("raw".to_string(), Some(self.raw.clone()));
        map
    }

    /// String representation
    fn __repr__(&self) -> String {
        format!(
            "LogEntry(timestamp={:?}, hostname={:?}, process={:?}, message={:?})",
            self.timestamp,
            self.hostname,
            self.process,
            if self.message.len() > 50 {
                format!("{}...", &self.message[..50])
            } else {
                self.message.clone()
            }
        )
    }

    /// String representation for print()
    fn __str__(&self) -> String {
        self.__repr__()
    }

    /// Check if entry has a timestamp
    fn has_timestamp(&self) -> bool {
        self.timestamp.is_some()
    }

    /// Check if entry has source IP
    fn has_source_ip(&self) -> bool {
        self.source_ip.is_some()
    }

    /// Check if entry has severity
    fn has_severity(&self) -> bool {
        self.severity.is_some()
    }

    /// Check if message contains a substring (case-insensitive)
    fn message_contains(&self, substring: &str) -> bool {
        self.message.to_lowercase().contains(&substring.to_lowercase())
    }

    /// Get all IP addresses found in the entry
    fn get_all_ips(&self) -> Vec<String> {
        let mut ips = Vec::new();
        if let Some(ref ip) = self.source_ip {
            ips.push(ip.clone());
        }
        if let Some(ref ip) = self.dest_ip {
            ips.push(ip.clone());
        }
        ips
    }
}

impl LogEntry {
    /// Builder pattern for creating LogEntry
    pub fn builder() -> LogEntryBuilder {
        LogEntryBuilder::default()
    }
}

/// Builder for LogEntry
#[derive(Default)]
pub struct LogEntryBuilder {
    entry: LogEntry,
}

impl LogEntryBuilder {
    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.entry.timestamp = Some(ts.into());
        self
    }

    pub fn hostname(mut self, h: impl Into<String>) -> Self {
        self.entry.hostname = Some(h.into());
        self
    }

    pub fn process(mut self, p: impl Into<String>) -> Self {
        self.entry.process = Some(p.into());
        self
    }

    pub fn pid(mut self, p: i32) -> Self {
        self.entry.pid = Some(p);
        self
    }

    pub fn severity(mut self, s: impl Into<String>) -> Self {
        self.entry.severity = Some(s.into());
        self
    }

    pub fn message(mut self, m: impl Into<String>) -> Self {
        self.entry.message = m.into();
        self
    }

    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.entry.source_ip = Some(ip.into());
        self
    }

    pub fn dest_ip(mut self, ip: impl Into<String>) -> Self {
        self.entry.dest_ip = Some(ip.into());
        self
    }

    pub fn user(mut self, u: impl Into<String>) -> Self {
        self.entry.user = Some(u.into());
        self
    }

    pub fn event_id(mut self, id: impl Into<String>) -> Self {
        self.entry.event_id = Some(id.into());
        self
    }

    pub fn raw(mut self, r: impl Into<String>) -> Self {
        self.entry.raw = r.into();
        self
    }

    pub fn build(self) -> LogEntry {
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let entry = LogEntry::builder()
            .timestamp("2025-01-01T00:00:00Z")
            .hostname("server01")
            .process("nginx")
            .pid(1234)
            .message("Test message")
            .source_ip("192.168.1.1")
            .raw("raw line")
            .build();

        assert_eq!(entry.timestamp.as_deref(), Some("2025-01-01T00:00:00Z"));
        assert_eq!(entry.hostname.as_deref(), Some("server01"));
        assert_eq!(entry.process.as_deref(), Some("nginx"));
        assert_eq!(entry.pid, Some(1234));
        assert_eq!(entry.message, "Test message");
        assert_eq!(entry.source_ip.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn test_to_dict() {
        let entry = LogEntry::builder()
            .timestamp("2025-01-01")
            .message("test")
            .build();

        let dict = entry.to_dict();
        assert_eq!(dict.get("timestamp"), Some(&Some("2025-01-01".to_string())));
        assert_eq!(dict.get("message"), Some(&Some("test".to_string())));
    }

    #[test]
    fn test_message_contains() {
        let entry = LogEntry::builder()
            .message("Failed password for user admin")
            .build();

        assert!(entry.message_contains("failed"));
        assert!(entry.message_contains("ADMIN"));
        assert!(!entry.message_contains("success"));
    }
}
