//! Format-specific parsing functions

use regex::Regex;
use crate::entry::LogEntry;

/// Parse syslog format (RFC3164 or BSD)
pub fn parse_syslog(
    line: &str,
    syslog_pattern: &Regex,
    rfc3164_pattern: &Regex,
) -> Option<LogEntry> {
    // Try RFC3164 with priority first
    if let Some(caps) = rfc3164_pattern.captures(line) {
        return Some(
            LogEntry::builder()
                .timestamp(caps.name("timestamp").map(|m| m.as_str()).unwrap_or(""))
                .hostname(caps.name("hostname").map(|m| m.as_str()).unwrap_or(""))
                .process(caps.name("tag").map(|m| m.as_str()).unwrap_or(""))
                .pid(caps
                    .name("pid")
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0) as i32)
                .message(caps.name("message").map(|m| m.as_str()).unwrap_or(""))
                .raw(line)
                .build(),
        );
    }

    // Try standard syslog
    if let Some(caps) = syslog_pattern.captures(line) {
        let pid = caps.name("pid").and_then(|m| m.as_str().parse::<i32>().ok());

        return Some(
            LogEntry::builder()
                .timestamp(caps.name("timestamp").map(|m| m.as_str()).unwrap_or(""))
                .hostname(caps.name("hostname").map(|m| m.as_str()).unwrap_or(""))
                .process(caps.name("process").map(|m| m.as_str()).unwrap_or(""))
                .pid(pid.unwrap_or(0))
                .message(caps.name("message").map(|m| m.as_str()).unwrap_or(""))
                .raw(line)
                .build(),
        );
    }

    None
}

/// Parse JSON log format
pub fn parse_json(line: &str) -> Option<LogEntry> {
    // Use simd-json for faster parsing if available, fall back to serde_json
    let data: serde_json::Value = serde_json::from_str(line).ok()?;

    let obj = data.as_object()?;

    // Extract common fields with flexible mapping
    let timestamp = obj
        .get("timestamp")
        .or_else(|| obj.get("time"))
        .or_else(|| obj.get("@timestamp"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let hostname = obj
        .get("hostname")
        .or_else(|| obj.get("host"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let process = obj
        .get("process")
        .or_else(|| obj.get("app"))
        .or_else(|| obj.get("application"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let pid = obj
        .get("pid")
        .and_then(|v| v.as_i64())
        .map(|p| p as i32);

    let severity = obj
        .get("level")
        .or_else(|| obj.get("severity"))
        .or_else(|| obj.get("log_level"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let message = obj
        .get("message")
        .or_else(|| obj.get("msg"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| line.to_string());

    let source_ip = obj
        .get("source_ip")
        .or_else(|| obj.get("src_ip"))
        .or_else(|| obj.get("client_ip"))
        .or_else(|| obj.get("remote_addr"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let dest_ip = obj
        .get("dest_ip")
        .or_else(|| obj.get("dst_ip"))
        .or_else(|| obj.get("destination_ip"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let user = obj
        .get("user")
        .or_else(|| obj.get("username"))
        .or_else(|| obj.get("user_name"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let event_id = obj
        .get("event_id")
        .or_else(|| obj.get("id"))
        .or_else(|| obj.get("eventId"))
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        });

    let mut entry = LogEntry::default();
    entry.timestamp = timestamp;
    entry.hostname = hostname;
    entry.process = process;
    entry.pid = pid;
    entry.severity = severity;
    entry.message = message;
    entry.source_ip = source_ip;
    entry.dest_ip = dest_ip;
    entry.user = user;
    entry.event_id = event_id;
    entry.raw = line.to_string();

    Some(entry)
}

/// Parse Apache Combined Log Format
pub fn parse_apache(line: &str, apache_pattern: &Regex, ip_pattern: &Regex) -> Option<LogEntry> {
    let caps = apache_pattern.captures(line)?;

    let request = caps.name("request").map(|m| m.as_str()).unwrap_or("");
    let status = caps.name("status").map(|m| m.as_str()).unwrap_or("");

    // Extract IPs from request if present
    let dest_ip = ip_pattern
        .find(request)
        .map(|m| m.as_str().to_string());

    let user = caps
        .name("user")
        .map(|m| m.as_str())
        .filter(|u| *u != "-")
        .map(String::from);

    Some(
        LogEntry::builder()
            .timestamp(caps.name("timestamp").map(|m| m.as_str()).unwrap_or(""))
            .source_ip(caps.name("ip").map(|m| m.as_str()).unwrap_or(""))
            .dest_ip(dest_ip.unwrap_or_default())
            .user(user.unwrap_or_default())
            .message(format!("{} {}", request, status))
            .raw(line)
            .build(),
    )
}

/// Parse Nginx log format
pub fn parse_nginx(line: &str, nginx_pattern: &Regex) -> Option<LogEntry> {
    let caps = nginx_pattern.captures(line)?;

    let request = caps.name("request").map(|m| m.as_str()).unwrap_or("");
    let status = caps.name("status").map(|m| m.as_str()).unwrap_or("");

    Some(
        LogEntry::builder()
            .timestamp(caps.name("timestamp").map(|m| m.as_str()).unwrap_or(""))
            .source_ip(caps.name("ip").map(|m| m.as_str()).unwrap_or(""))
            .message(format!("{} {}", request, status))
            .raw(line)
            .build(),
    )
}

/// Generic parser for unknown formats
pub fn parse_generic(line: &str, ip_pattern: &Regex, timestamp_patterns: &[Regex]) -> LogEntry {
    // Extract IPs
    let ips: Vec<&str> = ip_pattern.find_iter(line).map(|m| m.as_str()).collect();
    let source_ip = ips.first().map(|s| s.to_string());
    let dest_ip = ips.get(1).map(|s| s.to_string());

    // Try to extract timestamp
    let timestamp = timestamp_patterns
        .iter()
        .find_map(|pattern| pattern.find(line).map(|m| m.as_str().to_string()));

    let mut entry = LogEntry::default();
    entry.timestamp = timestamp;
    entry.source_ip = source_ip;
    entry.dest_ip = dest_ip;
    entry.message = line.to_string();
    entry.raw = line.to_string();
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    fn get_syslog_pattern() -> Regex {
        Regex::new(
            r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)"
        ).unwrap()
    }

    fn get_rfc3164_pattern() -> Regex {
        Regex::new(
            r"<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<tag>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)"
        ).unwrap()
    }

    fn get_apache_pattern() -> Regex {
        Regex::new(
            r#"(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)""#
        ).unwrap()
    }

    fn get_ip_pattern() -> Regex {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
    }

    #[test]
    fn test_parse_syslog_with_pid() {
        let line = "Oct 15 14:30:22 webserver01 sshd[12345]: Failed password for admin";
        let entry = parse_syslog(line, &get_syslog_pattern(), &get_rfc3164_pattern()).unwrap();

        assert_eq!(entry.timestamp.as_deref(), Some("Oct 15 14:30:22"));
        assert_eq!(entry.hostname.as_deref(), Some("webserver01"));
        assert_eq!(entry.process.as_deref(), Some("sshd"));
        assert_eq!(entry.pid, Some(12345));
        assert!(entry.message.contains("Failed password"));
    }

    #[test]
    fn test_parse_syslog_without_pid() {
        let line = "Oct 15 14:30:22 webserver01 kernel: Some kernel message";
        let entry = parse_syslog(line, &get_syslog_pattern(), &get_rfc3164_pattern()).unwrap();

        assert_eq!(entry.hostname.as_deref(), Some("webserver01"));
        assert_eq!(entry.process.as_deref(), Some("kernel"));
    }

    #[test]
    fn test_parse_json_standard() {
        let line = r#"{"timestamp":"2025-01-01T00:00:00Z","message":"Test","severity":"ERROR"}"#;
        let entry = parse_json(line).unwrap();

        assert_eq!(entry.timestamp.as_deref(), Some("2025-01-01T00:00:00Z"));
        assert_eq!(entry.message, "Test");
        assert_eq!(entry.severity.as_deref(), Some("ERROR"));
    }

    #[test]
    fn test_parse_json_alternative_fields() {
        let line = r#"{"time":"2025-01-01","msg":"Test","level":"INFO","src_ip":"10.0.0.1"}"#;
        let entry = parse_json(line).unwrap();

        assert_eq!(entry.timestamp.as_deref(), Some("2025-01-01"));
        assert_eq!(entry.message, "Test");
        assert_eq!(entry.severity.as_deref(), Some("INFO"));
        assert_eq!(entry.source_ip.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_parse_apache() {
        let line = r#"192.168.1.50 - admin [15/Oct/2025:14:30:22 +0000] "GET /api HTTP/1.1" 200 4523 "-" "curl""#;
        let entry = parse_apache(line, &get_apache_pattern(), &get_ip_pattern()).unwrap();

        assert_eq!(entry.source_ip.as_deref(), Some("192.168.1.50"));
        assert_eq!(entry.user.as_deref(), Some("admin"));
        assert!(entry.message.contains("GET /api"));
        assert!(entry.message.contains("200"));
    }

    #[test]
    fn test_parse_generic() {
        let timestamp_patterns = vec![
            Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}").unwrap(),
        ];
        let line = "2025-01-01T12:00:00 Connection from 192.168.1.1 to 10.0.0.1";
        let entry = parse_generic(line, &get_ip_pattern(), &timestamp_patterns);

        assert_eq!(entry.timestamp.as_deref(), Some("2025-01-01T12:00:00"));
        assert_eq!(entry.source_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(entry.dest_ip.as_deref(), Some("10.0.0.1"));
    }
}
