//! Benchmarks for the log parser
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use _log_parser_rs::LogParser;

const SYSLOG_LINES: &[&str] = &[
    "Oct 15 14:30:22 webserver01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "Oct 15 14:30:23 webserver01 nginx[5678]: 192.168.1.50 - - [15/Oct/2025:14:30:22 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
    "Oct 15 14:30:24 webserver01 kernel: [12345.678901] TCP: request_sock_TCP: Possible SYN flooding on port 80",
    "Oct 15 14:30:25 webserver01 systemd[1]: Started Session 42 of user admin.",
    "Oct 15 14:30:26 webserver01 sudo[9999]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls",
];

const JSON_LINES: &[&str] = &[
    r#"{"timestamp":"2025-10-15T14:30:22Z","severity":"ERROR","message":"Authentication failed","user":"admin","source_ip":"192.168.1.100"}"#,
    r#"{"timestamp":"2025-10-15T14:30:23Z","severity":"INFO","message":"Request processed","path":"/api/users","status":200}"#,
    r#"{"timestamp":"2025-10-15T14:30:24Z","severity":"WARN","message":"Rate limit exceeded","client":"192.168.1.50"}"#,
    r#"{"timestamp":"2025-10-15T14:30:25Z","severity":"DEBUG","message":"Cache hit","key":"user:42"}"#,
    r#"{"timestamp":"2025-10-15T14:30:26Z","severity":"INFO","message":"Connection established","host":"db.local"}"#,
];

const APACHE_LINES: &[&str] = &[
    r#"192.168.1.50 - - [15/Oct/2025:14:30:22 +0000] "GET /admin/login HTTP/1.1" 200 4523 "-" "Mozilla/5.0""#,
    r#"10.0.0.1 - admin [15/Oct/2025:14:30:23 +0000] "POST /api/data HTTP/1.1" 201 128 "https://example.com" "curl/7.68.0""#,
    r#"172.16.0.100 - - [15/Oct/2025:14:30:24 +0000] "GET /static/js/app.js HTTP/1.1" 304 0 "-" "Chrome/120.0""#,
    r#"192.168.1.1 - - [15/Oct/2025:14:30:25 +0000] "DELETE /api/users/42 HTTP/1.1" 403 256 "-" "PostmanRuntime""#,
    r#"10.10.10.10 - system [15/Oct/2025:14:30:26 +0000] "PUT /api/config HTTP/1.1" 200 64 "-" "Python/3.11""#,
];

fn benchmark_parse_line(c: &mut Criterion) {
    let syslog_parser = LogParser::new("syslog");
    let json_parser = LogParser::new("json");
    let apache_parser = LogParser::new("apache");
    let auto_parser = LogParser::new("auto");

    let mut group = c.benchmark_group("parse_line");

    // Syslog parsing
    group.bench_function("syslog", |b| {
        b.iter(|| {
            for line in SYSLOG_LINES {
                black_box(syslog_parser.parse_line(line));
            }
        })
    });

    // JSON parsing
    group.bench_function("json", |b| {
        b.iter(|| {
            for line in JSON_LINES {
                black_box(json_parser.parse_line(line));
            }
        })
    });

    // Apache parsing
    group.bench_function("apache", |b| {
        b.iter(|| {
            for line in APACHE_LINES {
                black_box(apache_parser.parse_line(line));
            }
        })
    });

    // Auto-detect parsing
    group.bench_function("auto_mixed", |b| {
        b.iter(|| {
            for line in SYSLOG_LINES {
                black_box(auto_parser.parse_line(line));
            }
            for line in JSON_LINES {
                black_box(auto_parser.parse_line(line));
            }
            for line in APACHE_LINES {
                black_box(auto_parser.parse_line(line));
            }
        })
    });

    group.finish();
}

fn benchmark_parse_batch(c: &mut Criterion) {
    let parser = LogParser::new("syslog");

    // Generate large batches
    let sizes = [100, 1_000, 10_000];

    let mut group = c.benchmark_group("parse_batch");

    for size in sizes {
        let lines: Vec<String> = SYSLOG_LINES
            .iter()
            .cycle()
            .take(size)
            .map(|s| s.to_string())
            .collect();

        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("sequential", size), &lines, |b, lines| {
            b.iter(|| {
                lines
                    .iter()
                    .filter_map(|line| parser.parse_line(line))
                    .count()
            })
        });

        group.bench_with_input(BenchmarkId::new("parallel", size), &lines, |b, lines| {
            b.iter(|| parser.parse_lines_parallel(lines.clone()))
        });
    }

    group.finish();
}

fn benchmark_regex_patterns(c: &mut Criterion) {
    use regex::Regex;

    let syslog_pattern = Regex::new(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)"
    ).unwrap();

    let ip_pattern = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap();

    let mut group = c.benchmark_group("regex");

    group.bench_function("syslog_match", |b| {
        b.iter(|| {
            for line in SYSLOG_LINES {
                black_box(syslog_pattern.captures(line));
            }
        })
    });

    group.bench_function("ip_extraction", |b| {
        b.iter(|| {
            for line in SYSLOG_LINES {
                black_box(ip_pattern.find_iter(line).collect::<Vec<_>>());
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_parse_line,
    benchmark_parse_batch,
    benchmark_regex_patterns,
);

criterion_main!(benches);
