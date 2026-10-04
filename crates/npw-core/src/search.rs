//! Search: every whitespace-separated term must appear in the item's text, or
//! match the pinyin of its title or tags. Each Chinese character may be typed
//! as any of its readings, in full or as the initial, so `zs`, `zsyh`,
//! `zhaoshang` and `zhaoshangyinhang` all find 招商银行 (行 is xing or hang).

use npw_model::ItemContent;
use pinyin::ToPinyinMulti;

/// What one character of a title can be typed as.
#[derive(Debug, Clone, PartialEq)]
enum Unit {
    /// Distinct plain readings of a Chinese character.
    Han(Vec<String>),
    /// Any other letter or digit, lower-cased.
    Other(char),
    /// Spaces and punctuation: may be skipped.
    Sep,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SearchIndex {
    text: String,
    units: Vec<Unit>,
}

fn has_han(s: &str) -> bool {
    s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c) || ('\u{3400}'..='\u{4dbf}').contains(&c))
}

fn units(s: &str) -> Vec<Unit> {
    let mut out = vec![];
    for (c, multi) in s.chars().zip(s.to_pinyin_multi()) {
        match multi {
            Some(m) => {
                let mut rs: Vec<String> = vec![];
                for i in 0..m.count() {
                    if let Some(p) = m.get_opt(i) {
                        let r = p.plain().to_string();
                        if !rs.contains(&r) {
                            rs.push(r);
                        }
                    }
                }
                out.push(Unit::Han(rs));
            }
            None if c.is_alphanumeric() => {
                for l in c.to_lowercase() {
                    out.push(Unit::Other(l));
                }
            }
            None => out.push(Unit::Sep),
        }
    }
    out
}

/// Can `term` be typed starting exactly at `units[i]`? The last character may
/// be typed partially (`zhaosh`).
fn match_from(units: &[Unit], i: usize, term: &[u8]) -> bool {
    if term.is_empty() {
        return true;
    }
    let Some(u) = units.get(i) else { return false };
    match u {
        Unit::Sep => match_from(units, i + 1, term),
        Unit::Other(c) => {
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf).as_bytes();
            term.starts_with(s) && match_from(units, i + 1, &term[s.len()..])
        }
        Unit::Han(readings) => readings.iter().any(|r| {
            let r = r.as_bytes();
            // full reading, or the reading's start when the term ends here
            (term.starts_with(r) && match_from(units, i + 1, &term[r.len()..]))
                || (r.starts_with(term))
                || (term[0] == r[0] && match_from(units, i + 1, &term[1..]))
        }),
    }
}

fn pinyin_matches(units: &[Unit], term: &str) -> bool {
    let t = term.as_bytes();
    (0..units.len()).any(|i| !matches!(units[i], Unit::Sep) && match_from(units, i, t))
}

fn pinyin_prefix(units: &[Unit], term: &str) -> bool {
    !units.is_empty() && match_from(units, 0, term.as_bytes())
}

/// The search index of an item.
pub fn index(c: &ItemContent) -> SearchIndex {
    let mut short = c.title.clone();
    for t in &c.tags {
        short.push(' ');
        short.push_str(t);
    }
    SearchIndex { text: c.search_text(), units: if has_han(&short) { units(&short) } else { vec![] } }
}

pub struct Query {
    terms: Vec<String>,
}

impl Query {
    pub fn parse(q: &str) -> Self {
        Self { terms: q.split_whitespace().map(str::to_lowercase).collect() }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn matches(&self, idx: &SearchIndex) -> bool {
        self.terms.iter().all(|t| idx.text.contains(t.as_str()) || (t.is_ascii() && pinyin_matches(&idx.units, t)))
    }

    /// Higher for title hits, highest for a title prefix (also in pinyin).
    pub fn score(&self, idx: &SearchIndex, title: &str) -> i64 {
        if self.terms.is_empty() {
            return 0;
        }
        let t = title.to_lowercase();
        let title_units = if has_han(title) { units(title) } else { vec![] };
        let mut s = 0;
        for term in &self.terms {
            if t.starts_with(term.as_str()) || (term.is_ascii() && pinyin_prefix(&title_units, term)) {
                s += 100;
            } else if t.contains(term.as_str()) || (term.is_ascii() && pinyin_matches(&title_units, term)) {
                s += 50;
            } else if idx.text.contains(term.as_str()) {
                s += 10;
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinyin_search() {
        let mut c = ItemContent::new("bank_account", "招商银行 储蓄账户");
        c.tags = vec!["金融".into()];
        let idx = index(&c);
        for q in ["zs", "zsyh", "zhaoshang", "zhaoshangyinhang", "zhaosh", "招商", "jr", "储蓄", "zhaoshang yinhang", "yhcx", "yinxing"] {
            assert!(Query::parse(q).matches(&idx), "{q}");
        }
        for q in ["gs", "zsx", "yhzs"] {
            assert!(!Query::parse(q).matches(&idx), "{q}");
        }
        assert!(Query::parse("zs").score(&idx, &c.title) > Query::parse("cx").score(&idx, &c.title));
    }

    #[test]
    fn latin_only() {
        let c = ItemContent::new("login", "GitHub");
        let idx = index(&c);
        assert!(Query::parse("git").matches(&idx));
        assert!(Query::parse("GIT hub").matches(&idx));
        assert!(!Query::parse("gitlab").matches(&idx));
    }
}
