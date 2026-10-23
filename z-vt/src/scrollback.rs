//! Page-allocated ring-buffer scrollback with flate2 compression for cold pages
//! and fast regex search across 100,000+ lines.

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use regex::Regex;
use std::collections::VecDeque;
use std::io::{Read, Write};

pub const LINES_PER_PAGE: usize = 64;
pub const DEFAULT_MAX_LINES: usize = 100_000;
pub const DEFAULT_HOT_PAGES: usize = 16; // 16 pages * 64 = 1024 hot lines

/// A single page of scrollback lines, stored either uncompressed in RAM (Hot)
/// or compressed with Deflate (Cold).
#[derive(Debug)]
pub enum ScrollPage {
    Hot(Vec<String>),
    Cold {
        compressed: Vec<u8>,
        line_count: usize,
    },
}

impl ScrollPage {
    pub fn new_hot() -> Self {
        ScrollPage::Hot(Vec::with_capacity(LINES_PER_PAGE))
    }

    pub fn is_hot(&self) -> bool {
        matches!(self, ScrollPage::Hot(_))
    }

    pub fn line_count(&self) -> usize {
        match self {
            ScrollPage::Hot(lines) => lines.len(),
            ScrollPage::Cold { line_count, .. } => *line_count,
        }
    }

    /// Compress this page if it is currently Hot.
    pub fn compress(&mut self) -> Result<(), std::io::Error> {
        if let ScrollPage::Hot(lines) = self {
            let joined = lines.join("\n");
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(joined.as_bytes())?;
            let compressed = encoder.finish()?;
            let line_count = lines.len();
            *self = ScrollPage::Cold {
                compressed,
                line_count,
            };
        }
        Ok(())
    }

    /// Extract all lines from this page, decompressing on-the-fly if Cold.
    pub fn read_lines(&self) -> Result<Vec<String>, std::io::Error> {
        match self {
            ScrollPage::Hot(lines) => Ok(lines.clone()),
            ScrollPage::Cold { compressed, .. } => {
                let mut decoder = DeflateDecoder::new(&compressed[..]);
                let mut decompressed = String::new();
                decoder.read_to_string(&mut decompressed)?;
                Ok(decompressed.lines().map(ToString::to_string).collect())
            }
        }
    }
}

/// High-capacity, memory-efficient page-allocated scrollback buffer.
pub struct PageScrollback {
    pages: VecDeque<ScrollPage>,
    max_lines: usize,
    hot_pages: usize,
    total_lines: usize,
}

impl Default for PageScrollback {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LINES, DEFAULT_HOT_PAGES)
    }
}

impl PageScrollback {
    pub fn new(max_lines: usize, hot_pages: usize) -> Self {
        let mut pages = VecDeque::new();
        pages.push_back(ScrollPage::new_hot());
        Self {
            pages,
            max_lines: max_lines.max(LINES_PER_PAGE),
            hot_pages: hot_pages.max(1),
            total_lines: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.total_lines
    }

    pub fn is_empty(&self) -> bool {
        self.total_lines == 0
    }

    /// Push a line into scrollback. Hot pages naturally roll over into compressed Cold pages.
    pub fn push_line(&mut self, line: String) {
        if self.pages.is_empty() {
            self.pages.push_back(ScrollPage::new_hot());
        }

        let need_new_page = match self.pages.back() {
            Some(ScrollPage::Hot(lines)) => lines.len() >= LINES_PER_PAGE,
            _ => true,
        };

        if need_new_page {
            self.pages.push_back(ScrollPage::new_hot());
        }

        if let Some(ScrollPage::Hot(lines)) = self.pages.back_mut() {
            lines.push(line);
            self.total_lines += 1;
        }

        // Compress older pages exceeding hot_pages budget
        let hot_count = self.pages.iter().filter(|p| p.is_hot()).count();
        if hot_count > self.hot_pages {
            for page in self.pages.iter_mut() {
                if page.is_hot() {
                    let _ = page.compress();
                    break;
                }
            }
        }

        // Evict oldest pages if over max_lines
        while self.total_lines > self.max_lines {
            if let Some(front) = self.pages.pop_front() {
                self.total_lines = self.total_lines.saturating_sub(front.line_count());
            } else {
                break;
            }
        }
    }

    /// Retrieve a specific line by index (0 is oldest line).
    pub fn get_line(&self, mut target_idx: usize) -> Option<String> {
        if target_idx >= self.total_lines {
            return None;
        }

        for page in &self.pages {
            let count = page.line_count();
            if target_idx < count {
                let lines = page.read_lines().ok()?;
                return lines.into_iter().nth(target_idx);
            }
            target_idx -= count;
        }

        None
    }

    /// Fast regex search across all scrollback pages without holding
    /// decompressed state simultaneously.
    pub fn search_regex(
        &self,
        query: &str,
        max_matches: usize,
    ) -> Result<Vec<(usize, String)>, regex::Error> {
        let re = Regex::new(query)?;
        let mut results = Vec::new();
        let mut base_line = 0;

        for page in &self.pages {
            if let Ok(lines) = page.read_lines() {
                for (page_idx, line) in lines.into_iter().enumerate() {
                    let absolute_line = base_line + page_idx;
                    if re.is_match(&line) {
                        results.push((absolute_line, line));
                        if results.len() >= max_matches {
                            return Ok(results);
                        }
                    }
                }
            }
            base_line += page.line_count();
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrollback_hot_to_cold_compression() {
        let mut sb = PageScrollback::new(1000, 2); // only 2 hot pages = 128 hot lines

        for i in 0..300 {
            sb.push_line(format!("Scrollback line number {i} - lots of repetitive text for compression"));
        }

        assert_eq!(sb.len(), 300);

        // Verify older pages are Cold and newest are Hot
        let cold_count = sb.pages.iter().filter(|p| !p.is_hot()).count();
        let hot_count = sb.pages.iter().filter(|p| p.is_hot()).count();
        assert!(cold_count >= 2);
        assert!(hot_count <= 3);

        // Verify accurate retrieval across cold pages
        assert_eq!(
            sb.get_line(0),
            Some("Scrollback line number 0 - lots of repetitive text for compression".into())
        );
        assert_eq!(
            sb.get_line(299),
            Some("Scrollback line number 299 - lots of repetitive text for compression".into())
        );
    }

    #[test]
    fn test_scrollback_fast_regex_search() {
        let mut sb = PageScrollback::new(10_000, 4);

        for i in 0..2000 {
            if i == 500 {
                sb.push_line("ERROR [SEC-403]: Unauthorized access attempt from 192.168.1.5".into());
            } else if i == 1500 {
                sb.push_line("ERROR [SEC-500]: Internal vault cryptographic exception".into());
            } else {
                sb.push_line(format!("INFO log entry {i} standard output stream"));
            }
        }

        let matches = sb.search_regex(r"ERROR \[SEC-\d+\]", 10).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].0, 500);
        assert!(matches[0].1.contains("SEC-403"));
        assert_eq!(matches[1].0, 1500);
        assert!(matches[1].1.contains("SEC-500"));
    }
}
