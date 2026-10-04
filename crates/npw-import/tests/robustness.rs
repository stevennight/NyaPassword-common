//! Garbage, truncated and mutated input must give `Err` (or a harmless `Ok`), never a panic.

use npw_import::{detect, import, Source};
use rand::{rngs::StdRng, Rng, SeedableRng};

const ALL: [Source; 9] = [
    Source::BitwardenJson,
    Source::BitwardenEncryptedJson,
    Source::BitwardenZip,
    Source::BitwardenCsv,
    Source::ChromeCsv,
    Source::OnePasswordPux,
    Source::OnePasswordCsv,
    Source::KeepassKdbx,
    Source::KeepassCsv,
];

fn run(source: Source, bytes: &[u8]) -> Result<bool, String> {
    std::panic::catch_unwind(|| {
        let _ = detect("input.bin", bytes);
        import(source, bytes, Some("password"), "zh-CN").is_ok()
    })
    .map_err(|_| {
        format!(
            "{source:?} panicked on {} bytes: {:02x?}",
            bytes.len(),
            &bytes[..bytes.len().min(64)]
        )
    })
}

#[test]
fn random_bytes_are_rejected() {
    let mut rng = StdRng::seed_from_u64(0x6e79_6170_6173);
    for i in 0..2000 {
        let len = rng.gen_range(0..2048);
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        // Make some inputs start like the real thing so parsers get past the first check.
        match i % 5 {
            1 if len >= 4 => bytes[..4].copy_from_slice(b"PK\x03\x04"),
            2 if len >= 8 => {
                bytes[..8].copy_from_slice(&[0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5])
            }
            3 if len >= 1 => bytes[0] = b'{',
            _ => {}
        }
        for s in ALL {
            assert_eq!(
                run(s, &bytes),
                Ok(false),
                "{s:?} accepted random input #{i}"
            );
        }
    }
}

#[test]
fn truncated_and_mutated_exports_do_not_panic() {
    let json = include_bytes!("fixtures/bitwarden_export.json").as_slice();
    let csvs: [&[u8]; 3] = [
        include_bytes!("fixtures/bitwarden_export.csv"),
        include_bytes!("fixtures/chrome_passwords.csv"),
        include_bytes!("fixtures/firefox_passwords.csv"),
    ];
    let mut rng = StdRng::seed_from_u64(42);
    // Every truncation of the JSON export is invalid JSON.
    for cut in (0..json.len() - 1).step_by(7) {
        for s in [Source::BitwardenJson, Source::BitwardenEncryptedJson] {
            assert_eq!(run(s, &json[..cut]), Ok(false), "truncated at {cut}");
        }
    }
    // Random byte mutations of every fixture, fed to every importer.
    let fixtures: Vec<&[u8]> = std::iter::once(json).chain(csvs).collect();
    for i in 0..1500 {
        let mut bytes = fixtures[i % fixtures.len()].to_vec();
        for _ in 0..rng.gen_range(1..8) {
            let at = rng.gen_range(0..bytes.len());
            match rng.gen_range(0..3) {
                0 => bytes[at] = rng.gen(),
                1 => {
                    bytes.remove(at);
                }
                _ => bytes.insert(
                    at,
                    *b"{}[]\",:\n\r\\0"
                        .get(rng.gen_range(0..12))
                        .unwrap_or(&b'x'),
                ),
            }
        }
        if rng.gen_bool(0.3) {
            bytes.truncate(rng.gen_range(0..bytes.len()));
        }
        for s in ALL {
            run(s, &bytes).unwrap();
        }
    }
}
