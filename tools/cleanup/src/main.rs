//! Rust Cleanup Tool for defensive-toolkit

use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

struct CleanupStats {
    removed: usize,
    failed: usize,
}

impl CleanupStats {
    fn new() -> Self {
        CleanupStats { removed: 0, failed: 0 }
    }
}

fn cleanup_pycache(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing __pycache__ directories...".blue());
    let mut stats = CleanupStats::new();
    for entry in WalkDir::new(base_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() && path.file_name().map(|n| n == "__pycache__").unwrap_or(false) {
            match fs::remove_dir_all(path) {
                Ok(_) => { println!("    Removed: {}", path.display()); stats.removed += 1; }
                Err(e) => { println!("    [!] Failed: {}: {}", path.display(), e); stats.failed += 1; }
            }
        }
    }
    println!("[OK] Removed {} __pycache__ directories\n", stats.removed);
    Ok(stats)
}

fn cleanup_pyc_files(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing .pyc/.pyo files...".blue());
    let mut stats = CleanupStats::new();
    for entry in WalkDir::new(base_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == "pyc" || ext == "pyo" {
                match fs::remove_file(path) {
                    Ok(_) => stats.removed += 1,
                    Err(e) => { println!("    [!] Failed: {}: {}", path.display(), e); stats.failed += 1; }
                }
            }
        }
    }
    println!("[OK] Removed {} compiled Python files\n", stats.removed);
    Ok(stats)
}

fn cleanup_logs(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing .log files...".blue());
    let mut stats = CleanupStats::new();
    for entry in WalkDir::new(base_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().map(|e| e == "log").unwrap_or(false) {
            match fs::remove_file(path) {
                Ok(_) => { println!("    Removed: {}", path.display()); stats.removed += 1; }
                Err(e) => { println!("    [!] Failed: {}: {}", path.display(), e); stats.failed += 1; }
            }
        }
    }
    println!("[OK] Removed {} log files\n", stats.removed);
    Ok(stats)
}

fn cleanup_os_files(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing OS-specific files...".blue());
    let mut stats = CleanupStats::new();
    let os_files = [".DS_Store", "Thumbs.db", "desktop.ini"];
    for entry in WalkDir::new(base_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if os_files.contains(&name) {
                match fs::remove_file(path) {
                    Ok(_) => { println!("    Removed: {}", path.display()); stats.removed += 1; }
                    Err(e) => { println!("    [!] Failed: {}: {}", path.display(), e); stats.failed += 1; }
                }
            }
        }
    }
    println!("[OK] Removed {} OS-specific files\n", stats.removed);
    Ok(stats)
}

fn cleanup_pytest_cache(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing pytest cache...".blue());
    let mut stats = CleanupStats::new();
    let cache_path = base_path.join(".pytest_cache");
    if cache_path.exists() {
        match fs::remove_dir_all(&cache_path) {
            Ok(_) => { println!("    Removed: {}", cache_path.display()); stats.removed += 1; }
            Err(e) => { println!("    [!] Failed: {}", e); stats.failed += 1; }
        }
    } else {
        println!("    No pytest cache found");
    }
    println!("[OK] Done with pytest cache\n");
    Ok(stats)
}

fn cleanup_coverage(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing coverage files...".blue());
    let mut stats = CleanupStats::new();
    for filename in &[".coverage", "coverage.json", "coverage.xml"] {
        let file_path = base_path.join(filename);
        if file_path.exists() {
            match fs::remove_file(&file_path) {
                Ok(_) => { println!("    Removed: {}", file_path.display()); stats.removed += 1; }
                Err(e) => { println!("    [!] Failed: {}: {}", file_path.display(), e); stats.failed += 1; }
            }
        }
    }
    let htmlcov = base_path.join("htmlcov");
    if htmlcov.exists() {
        match fs::remove_dir_all(&htmlcov) {
            Ok(_) => { println!("    Removed: {}", htmlcov.display()); stats.removed += 1; }
            Err(e) => { println!("    [!] Failed: {}: {}", htmlcov.display(), e); stats.failed += 1; }
        }
    }
    println!("[OK] Removed {} coverage files\n", stats.removed);
    Ok(stats)
}

fn cleanup_temp_files(base_path: &Path) -> Result<CleanupStats> {
    println!("{}", "[+] Removing temporary files...".blue());
    let mut stats = CleanupStats::new();
    let temp_ext = ["tmp", "temp", "bak", "backup"];
    for entry in WalkDir::new(base_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() { continue; }
        let remove = path.extension().and_then(|e| e.to_str()).map(|e| temp_ext.contains(&e)).unwrap_or(false)
            || path.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with('~')).unwrap_or(false);
        if remove {
            match fs::remove_file(path) {
                Ok(_) => { println!("    Removed: {}", path.display()); stats.removed += 1; }
                Err(e) => { println!("    [!] Failed: {}: {}", path.display(), e); stats.failed += 1; }
            }
        }
    }
    println!("[OK] Removed {} temporary files\n", stats.removed);
    Ok(stats)
}

fn main() -> Result<()> {
    let current_dir = std::env::current_dir()?;
    println!("{}", "=".repeat(70).blue());
    println!("{}", "Defensive Toolkit - Deep Cleanup (Rust)".blue().bold());
    println!("{}", "=".repeat(70).blue());
    println!();
    cleanup_pycache(&current_dir)?;
    cleanup_pyc_files(&current_dir)?;
    cleanup_logs(&current_dir)?;
    cleanup_os_files(&current_dir)?;
    cleanup_pytest_cache(&current_dir)?;
    cleanup_coverage(&current_dir)?;
    cleanup_temp_files(&current_dir)?;
    println!("{}", "=".repeat(70).green());
    println!("{}", "[OK] Deep cleanup completed!".green().bold());
    println!("{}", "=".repeat(70).green());
    Ok(())
}
