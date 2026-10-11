//! Password / username generator and strength estimate.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?.:,~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recipe {
    /// Random characters.
    Random {
        length: u32,
        upper: bool,
        lower: bool,
        digits: bool,
        symbols: bool,
        /// Leave out look-alike characters (I l 1 O 0 ...).
        #[serde(default)]
        avoid_ambiguous: bool,
    },
    /// Pronounceable syllable groups, e.g. `Kabo-temu-risa-74`.
    Memorable {
        /// Number of groups.
        words: u32,
        #[serde(default = "dash")]
        separator: String,
        #[serde(default)]
        capitalize: bool,
        #[serde(default)]
        digits: bool,
    },
    /// Digits only.
    Pin { length: u32 },
    /// A username that reads like one: words (`QuietOtter472`) or a made-up
    /// name (`Kavomi`), not random characters. The result is in `password`.
    Username {
        #[serde(default)]
        style: UsernameStyle,
        /// Words (style `words`, 2–3) or syllables (style `name`, 2–5).
        #[serde(default = "two")]
        words: u32,
        /// Between words (style `words` only).
        #[serde(default)]
        separator: String,
        #[serde(default)]
        capitalize: bool,
        /// A 2–4 digit number at the end.
        #[serde(default)]
        digits: bool,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsernameStyle {
    /// Adjective(s) + noun, e.g. `quiet_otter`.
    #[default]
    Words,
    /// Pronounceable syllables, e.g. `kavomi`.
    Name,
}

fn two() -> u32 {
    2
}

fn dash() -> String {
    "-".into()
}

impl Default for Recipe {
    fn default() -> Self {
        Recipe::Random {
            length: 20,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

const CONSONANTS: &[&str] = &[
    "b", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "w", "z", "ch",
    "sh", "x",
];
const VOWELS: &[&str] = &["a", "e", "i", "o", "u", "ai", "ao", "ei", "ou", "an"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Generated {
    /// The generated value (also a username, for `Recipe::Username`).
    pub password: String,
    /// Entropy of the recipe in bits.
    pub bits: f64,
}

pub fn generate(recipe: &Recipe) -> Generated {
    let mut rng = rand::rngs::OsRng;
    match recipe {
        Recipe::Random {
            length,
            upper,
            lower,
            digits,
            symbols,
            avoid_ambiguous,
        } => {
            let filter = |s: &str| -> Vec<char> {
                s.chars()
                    .filter(|c| !*avoid_ambiguous || !AMBIGUOUS.contains(*c))
                    .collect()
            };
            let mut sets: Vec<Vec<char>> = vec![];
            if *upper {
                sets.push(filter(UPPER));
            }
            if *lower {
                sets.push(filter(LOWER));
            }
            if *digits {
                sets.push(filter(DIGITS));
            }
            if *symbols {
                sets.push(filter(SYMBOLS));
            }
            if sets.is_empty() {
                sets.push(filter(LOWER));
            }
            let length = (*length).clamp(4, 128) as usize;
            let all: Vec<char> = sets.iter().flatten().copied().collect();
            // one character from every chosen set, the rest from all, then shuffle
            let mut chars: Vec<char> = sets
                .iter()
                .take(length)
                .map(|s| *s.choose(&mut rng).expect("non-empty set"))
                .collect();
            while chars.len() < length {
                chars.push(*all.choose(&mut rng).expect("non-empty"));
            }
            chars.shuffle(&mut rng);
            Generated {
                password: chars.into_iter().collect(),
                bits: length as f64 * (all.len() as f64).log2(),
            }
        }
        Recipe::Memorable {
            words,
            separator,
            capitalize,
            digits,
        } => {
            let words = (*words).clamp(2, 12);
            let mut parts = vec![];
            for _ in 0..words {
                let mut w = String::new();
                for _ in 0..2 {
                    w.push_str(CONSONANTS.choose(&mut rng).expect("non-empty"));
                    w.push_str(VOWELS.choose(&mut rng).expect("non-empty"));
                }
                if *capitalize && rng.gen_bool(0.5) {
                    let mut cs = w.chars();
                    w = cs
                        .next()
                        .map(|f| f.to_uppercase().collect::<String>() + cs.as_str())
                        .unwrap_or(w);
                }
                parts.push(w);
            }
            let mut bits = words as f64 * 2.0 * ((CONSONANTS.len() * VOWELS.len()) as f64).log2();
            if *capitalize {
                bits += words as f64;
            }
            if *digits {
                parts.push(format!("{:02}", rng.gen_range(0..100)));
                bits += (100f64).log2();
            }
            Generated {
                password: parts.join(separator),
                bits,
            }
        }
        Recipe::Username {
            style,
            words,
            separator,
            capitalize,
            digits,
        } => {
            let cap = |w: &str| -> String {
                if !*capitalize {
                    return w.to_string();
                }
                let mut cs = w.chars();
                cs.next()
                    .map(|f| f.to_ascii_uppercase().to_string() + cs.as_str())
                    .unwrap_or_default()
            };
            let (mut name, mut bits) = match style {
                UsernameStyle::Words => {
                    let n = (*words).clamp(2, 3) as usize;
                    // different adjectives first, then a noun
                    let mut parts: Vec<String> = ADJECTIVES
                        .choose_multiple(&mut rng, n - 1)
                        .map(|w| cap(w))
                        .collect();
                    parts.push(cap(NOUNS.choose(&mut rng).expect("non-empty")));
                    let mut bits = (NOUNS.len() as f64).log2();
                    for i in 0..n - 1 {
                        bits += ((ADJECTIVES.len() - i) as f64).log2();
                    }
                    (parts.join(separator), bits)
                }
                UsernameStyle::Name => {
                    let n = (*words).clamp(2, 5);
                    let mut w = String::new();
                    for _ in 0..n {
                        w.push_str(NAME_CONSONANTS.choose(&mut rng).expect("non-empty"));
                        w.push_str(NAME_VOWELS.choose(&mut rng).expect("non-empty"));
                    }
                    let bits =
                        n as f64 * ((NAME_CONSONANTS.len() * NAME_VOWELS.len()) as f64).log2();
                    (cap(&w), bits)
                }
            };
            if *digits {
                name.push_str(&rng.gen_range(10..10_000u32).to_string());
                bits += 9_990f64.log2();
            }
            Generated {
                password: name,
                bits,
            }
        }
        Recipe::Pin { length } => {
            let length = (*length).clamp(3, 32);
            let s: String = (0..length)
                .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
                .collect();
            Generated {
                password: s,
                bits: length as f64 * 10f64.log2(),
            }
        }
    }
}

// Short, friendly English words for usernames (lowercase ASCII, no repeats).
const ADJECTIVES: &[&str] = &[
    "agile",
    "amber",
    "ancient",
    "arctic",
    "azure",
    "bold",
    "brave",
    "breezy",
    "bright",
    "brisk",
    "calm",
    "candid",
    "cheery",
    "clever",
    "cosmic",
    "cozy",
    "crimson",
    "crisp",
    "curious",
    "daring",
    "dapper",
    "dreamy",
    "dusky",
    "eager",
    "early",
    "electric",
    "epic",
    "fancy",
    "fearless",
    "fluffy",
    "frosty",
    "fuzzy",
    "gentle",
    "giant",
    "gilded",
    "glad",
    "golden",
    "grand",
    "happy",
    "hidden",
    "humble",
    "icy",
    "indigo",
    "jade",
    "jolly",
    "keen",
    "kind",
    "lazy",
    "little",
    "lively",
    "lucky",
    "lunar",
    "magic",
    "mellow",
    "merry",
    "mighty",
    "misty",
    "modest",
    "mossy",
    "neat",
    "nimble",
    "noble",
    "odd",
    "olive",
    "polar",
    "proud",
    "purple",
    "quick",
    "quiet",
    "rapid",
    "rosy",
    "royal",
    "rusty",
    "sandy",
    "scarlet",
    "secret",
    "shiny",
    "silent",
    "silver",
    "sleepy",
    "sly",
    "smart",
    "snowy",
    "solar",
    "sonic",
    "spicy",
    "steady",
    "stellar",
    "stormy",
    "sunny",
    "swift",
    "tidy",
    "tiny",
    "true",
    "twin",
    "urban",
    "velvet",
    "vivid",
    "wandering",
    "warm",
    "wild",
    "windy",
    "wise",
    "witty",
    "young",
    "zesty",
];
const NOUNS: &[&str] = &[
    "acorn", "anchor", "arrow", "badger", "bamboo", "beacon", "bear", "beetle", "birch", "bison",
    "blossom", "breeze", "brook", "cactus", "canyon", "cedar", "cloud", "comet", "coral",
    "cricket", "crow", "dolphin", "dragon", "dune", "eagle", "ember", "falcon", "fern", "finch",
    "fox", "galaxy", "gecko", "glacier", "harbor", "hawk", "hedgehog", "heron", "island", "ivy",
    "jaguar", "koala", "lagoon", "lantern", "lark", "lemon", "leopard", "lily", "lion", "lotus",
    "lynx", "maple", "meadow", "meteor", "mango", "moon", "moth", "nebula", "nova", "oak", "ocean",
    "orbit", "orca", "otter", "owl", "panda", "panther", "parrot", "pebble", "pepper", "phoenix",
    "pine", "pixel", "planet", "plum", "pony", "puffin", "quartz", "rabbit", "raven", "reef",
    "river", "robin", "rocket", "sparrow", "sprout", "squirrel", "star", "storm", "summit", "swan",
    "tiger", "tulip", "turtle", "valley", "violet", "walrus", "willow", "wolf", "wren", "yak",
    "zebra",
];
const NAME_CONSONANTS: &[&str] = &[
    "b", "d", "f", "g", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z",
];
const NAME_VOWELS: &[&str] = &["a", "e", "i", "o", "u"];

/// 0 (very weak) to 4 (very strong), for passwords people chose themselves.
pub fn strength(password: &str) -> u8 {
    let len = password.chars().count();
    if len == 0 {
        return 0;
    }
    let lower = password.to_lowercase();
    const COMMON: &[&str] = &[
        "password", "123456", "qwerty", "abc123", "111111", "iloveyou", "admin", "welcome",
        "woaini", "5201314", "88888888", "000000", "123123",
    ];
    if COMMON.iter().any(|c| lower.contains(c)) && len < 14 {
        return 0;
    }
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 20;
    }
    let distinct = password
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    // repeated characters and sequences add little
    let effective = len.min(distinct * 2) as f64;
    let bits = effective * (pool.max(10) as f64).log2();
    match bits {
        b if b < 28.0 => 0,
        b if b < 40.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_has_every_set() {
        for _ in 0..200 {
            let g = generate(&Recipe::Random {
                length: 8,
                upper: true,
                lower: true,
                digits: true,
                symbols: true,
                avoid_ambiguous: true,
            });
            let p = &g.password;
            assert_eq!(p.chars().count(), 8);
            assert!(
                p.chars().any(|c| c.is_ascii_uppercase())
                    && p.chars().any(|c| c.is_ascii_lowercase())
            );
            assert!(
                p.chars().any(|c| c.is_ascii_digit()) && p.chars().any(|c| SYMBOLS.contains(c))
            );
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        assert!(generate(&Recipe::default()).bits > 100.0);
    }

    #[test]
    fn memorable_and_pin() {
        let g = generate(&Recipe::Memorable {
            words: 4,
            separator: "-".into(),
            capitalize: true,
            digits: true,
        });
        assert_eq!(g.password.split('-').count(), 5);
        let pin = generate(&Recipe::Pin { length: 6 });
        assert!(pin.password.len() == 6 && pin.password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn username_words_and_name() {
        for _ in 0..200 {
            let g = generate(&Recipe::Username {
                style: UsernameStyle::Words,
                words: 3,
                separator: "_".into(),
                capitalize: false,
                digits: true,
            });
            let parts: Vec<&str> = g.password.split('_').collect();
            assert_eq!(parts.len(), 3, "{}", g.password);
            assert!(ADJECTIVES.contains(&parts[0]) && ADJECTIVES.contains(&parts[1]));
            assert_ne!(parts[0], parts[1]);
            let noun = parts[2].trim_end_matches(|c: char| c.is_ascii_digit());
            assert!(NOUNS.contains(&noun), "{}", g.password);
            let num: u32 = parts[2][noun.len()..].parse().unwrap();
            assert!((10..10_000).contains(&num));
        }
        let g = generate(&Recipe::Username {
            style: UsernameStyle::Words,
            words: 2,
            separator: String::new(),
            capitalize: true,
            digits: false,
        });
        assert!(g.password.chars().all(|c| c.is_ascii_alphabetic()));
        assert_eq!(
            g.password
                .chars()
                .filter(|c| c.is_ascii_uppercase())
                .count(),
            2
        );
        let n = generate(&Recipe::Username {
            style: UsernameStyle::Name,
            words: 3,
            separator: "-".into(),
            capitalize: true,
            digits: false,
        });
        assert_eq!(n.password.len(), 6);
        assert!(n.password.starts_with(|c: char| c.is_ascii_uppercase()));
        assert!(n.password[1..].chars().all(|c| c.is_ascii_lowercase()));
        // a bare `{"kind":"username"}` works (every option has a default)
        let r: Recipe = serde_json::from_str(r#"{"kind":"username"}"#).unwrap();
        assert!(matches!(
            r,
            Recipe::Username {
                style: UsernameStyle::Words,
                words: 2,
                ..
            }
        ));
        assert!(generate(&r).bits > 13.0);
    }

    #[test]
    fn username_word_lists_are_clean() {
        for list in [ADJECTIVES, NOUNS] {
            let set: std::collections::HashSet<_> = list.iter().collect();
            assert_eq!(set.len(), list.len(), "duplicate word");
            assert!(list
                .iter()
                .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase())));
        }
        assert!(ADJECTIVES.len() >= 100 && NOUNS.len() >= 100);
    }

    #[test]
    fn strength_scale() {
        assert_eq!(strength("123456"), 0);
        assert_eq!(strength("password1"), 0);
        assert!(strength("Tr0ub4dor&3") >= 2);
        assert_eq!(strength(&generate(&Recipe::default()).password), 4);
        assert!(strength("aaaaaaaaaaaaaaaaaaaa") <= 1);
    }
}
