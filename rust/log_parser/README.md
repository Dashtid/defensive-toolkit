# Log Parser (Rust)

High-performance log parser with Python bindings using PyO3.

## Performance

| Operation              | Python | Rust   | Speedup   |
| ---------------------- | ------ | ------ | --------- |
| Parse 1M syslog lines  | ~20s   | ~0.2s  | **100x**  |
| Parse 1M JSON lines    | ~15s   | ~0.3s  | **50x**   |
| Parse 1M Apache logs   | ~25s   | ~0.25s | **100x**  |

## Building

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Python 3.10+
- maturin (`pip install maturin`)

### Development Build

```bash
cd rust/log_parser
maturin develop --release
```

### Production Build

```bash
# From project root
uv run maturin build --release --manifest-path rust/log_parser/Cargo.toml --out dist
uv pip install dist/log_parser_rs-*.whl
```

## Usage

```python
from defensive_toolkit.log_analysis.parsers.log_parser_fast import LogParser

# Create parser (uses Rust backend automatically)
parser = LogParser(log_format="auto")

# Check which backend is active
print(f"Using backend: {parser.backend}")  # "rust" or "python"

# Parse a single line
entry = parser.parse_line("Oct 15 14:30:22 server sshd[1234]: Failed password")
print(entry.to_dict())

# Parse file (sequential)
entries = parser.parse_file("/var/log/syslog")

# Parse file (parallel - Rust only, 10x faster for large files)
entries = parser.parse_file_parallel("/var/log/syslog", chunk_size=10000)

# Parse multiple lines in parallel
lines = ["line1", "line2", "line3"]
entries = parser.parse_lines_parallel(lines)
```

## API Reference

### LogParser

- `__init__(log_format="auto")` - Create parser
- `parse_line(line)` - Parse single line, returns LogEntry or None
- `parse_file(path, max_lines=None)` - Parse file sequentially
- `parse_file_parallel(path, max_lines=None, chunk_size=10000)` - Parse file in parallel
- `parse_lines_parallel(lines)` - Parse list of lines in parallel
- `backend` - Property returning "rust" or "python"

### LogEntry

Fields:

- `timestamp` - Timestamp string
- `hostname` - Source hostname
- `process` - Process/application name
- `pid` - Process ID
- `severity` - Log level (ERROR, WARN, INFO, etc.)
- `message` - Log message content
- `source_ip` - Source IP address
- `dest_ip` - Destination IP address
- `user` - Username
- `event_id` - Event ID
- `raw` - Original raw log line

Methods:

- `to_dict()` - Convert to dictionary

## Supported Formats

- **auto** - Auto-detect format
- **syslog** - BSD/RFC3164 syslog
- **json** - JSON structured logs
- **apache** - Apache Combined Log Format
- **nginx** - Nginx access logs

## Architecture

```text
rust/log_parser/
├── Cargo.toml          # Rust dependencies
├── pyproject.toml      # Maturin configuration
├── README.md           # This file
└── src/
    ├── lib.rs          # Main module, PyO3 bindings
    ├── entry.rs        # LogEntry struct
    ├── formats.rs      # Format-specific parsers
    └── parallel.rs     # Parallel processing utilities
```

## Fallback Behavior

If the Rust module is not installed, the Python wrapper automatically
falls back to the pure Python implementation with a warning:

```python
from defensive_toolkit.log_analysis.parsers.log_parser_fast import is_rust_available

if is_rust_available():
    print("Using Rust backend")
else:
    print("Using Python fallback")
```
