//! Parallel processing utilities for log parsing
//!
//! This module provides streaming and parallel processing capabilities
//! for handling large log files efficiently.
//!
//! Note: These utilities are currently used internally and may be exposed
//! via Python bindings in future versions.

#![allow(dead_code)]

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::entry::LogEntry;
use crate::LogParser;

/// Memory-mapped file reader for very large files
pub struct MmapReader {
    mmap: Mmap,
}

impl MmapReader {
    /// Open a file with memory mapping
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(MmapReader { mmap })
    }

    /// Get lines iterator
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.mmap
            .split(|&b| b == b'\n')
            .filter_map(|line| std::str::from_utf8(line).ok())
            .filter(|line| !line.is_empty())
    }

    /// Parse all lines with a parser
    pub fn parse_all(&self, parser: &LogParser) -> Vec<LogEntry> {
        self.lines()
            .filter_map(|line| parser.parse_line(line))
            .collect()
    }

    /// Parse all lines in parallel
    pub fn parse_all_parallel(&self, parser: &LogParser, chunk_size: usize) -> Vec<LogEntry> {
        let lines: Vec<&str> = self.lines().collect();

        lines
            .par_chunks(chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .filter_map(|line| parser.parse_line(line))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Streaming log file reader
pub struct StreamingReader<R: BufRead> {
    reader: R,
    buffer: String,
}

impl<R: BufRead> StreamingReader<R> {
    /// Create a new streaming reader
    pub fn new(reader: R) -> Self {
        StreamingReader {
            reader,
            buffer: String::with_capacity(4096),
        }
    }

    /// Read the next line
    pub fn next_line(&mut self) -> std::io::Result<Option<&str>> {
        self.buffer.clear();
        match self.reader.read_line(&mut self.buffer)? {
            0 => Ok(None),
            _ => {
                // Trim trailing newline
                if self.buffer.ends_with('\n') {
                    self.buffer.pop();
                    if self.buffer.ends_with('\r') {
                        self.buffer.pop();
                    }
                }
                Ok(Some(&self.buffer))
            }
        }
    }
}

impl StreamingReader<BufReader<File>> {
    /// Open a file for streaming
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(64 * 1024, file); // 64KB buffer
        Ok(StreamingReader::new(reader))
    }
}

/// Chunk-based parallel processor
pub struct ChunkedProcessor {
    chunk_size: usize,
}

impl ChunkedProcessor {
    /// Create a new chunked processor
    pub fn new(chunk_size: usize) -> Self {
        ChunkedProcessor { chunk_size }
    }

    /// Process lines in parallel chunks
    pub fn process<F>(&self, lines: Vec<String>, processor: F) -> Vec<LogEntry>
    where
        F: Fn(&str) -> Option<LogEntry> + Sync,
    {
        lines
            .par_chunks(self.chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .filter_map(|line| processor(line))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Process with statistics collection
    pub fn process_with_stats<F>(
        &self,
        lines: Vec<String>,
        processor: F,
    ) -> (Vec<LogEntry>, ProcessingStats)
    where
        F: Fn(&str) -> Option<LogEntry> + Sync,
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let total = AtomicUsize::new(0);
        let parsed = AtomicUsize::new(0);
        let failed = AtomicUsize::new(0);

        let entries: Vec<LogEntry> = lines
            .par_chunks(self.chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .filter_map(|line| {
                        total.fetch_add(1, Ordering::Relaxed);
                        match processor(line) {
                            Some(entry) => {
                                parsed.fetch_add(1, Ordering::Relaxed);
                                Some(entry)
                            }
                            None => {
                                failed.fetch_add(1, Ordering::Relaxed);
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let stats = ProcessingStats {
            total_lines: total.load(Ordering::Relaxed),
            parsed_lines: parsed.load(Ordering::Relaxed),
            failed_lines: failed.load(Ordering::Relaxed),
        };

        (entries, stats)
    }
}

/// Processing statistics
#[derive(Debug, Clone)]
pub struct ProcessingStats {
    pub total_lines: usize,
    pub parsed_lines: usize,
    pub failed_lines: usize,
}

impl ProcessingStats {
    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_lines == 0 {
            0.0
        } else {
            (self.parsed_lines as f64 / self.total_lines as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_streaming_reader() {
        let data = "line1\nline2\nline3\n";
        let cursor = Cursor::new(data);
        let reader = BufReader::new(cursor);
        let mut streaming = StreamingReader::new(reader);

        assert_eq!(streaming.next_line().unwrap(), Some("line1"));
        assert_eq!(streaming.next_line().unwrap(), Some("line2"));
        assert_eq!(streaming.next_line().unwrap(), Some("line3"));
        assert_eq!(streaming.next_line().unwrap(), None);
    }

    #[test]
    fn test_chunked_processor() {
        let lines: Vec<String> = (0..100).map(|i| format!("line {}", i)).collect();
        let processor = ChunkedProcessor::new(10);

        let entries = processor.process(lines, |line| {
            Some(LogEntry::builder().message(line).build())
        });

        assert_eq!(entries.len(), 100);
    }

    #[test]
    fn test_processing_stats() {
        let lines: Vec<String> = vec![
            "valid line".to_string(),
            "".to_string(), // will be filtered by empty check
            "another valid".to_string(),
        ];

        let processor = ChunkedProcessor::new(10);
        let (entries, stats) = processor.process_with_stats(lines, |line| {
            if line.is_empty() {
                None
            } else {
                Some(LogEntry::builder().message(line).build())
            }
        });

        assert_eq!(entries.len(), 2);
        assert_eq!(stats.total_lines, 3);
        assert_eq!(stats.parsed_lines, 2);
        assert_eq!(stats.failed_lines, 1);
    }
}
