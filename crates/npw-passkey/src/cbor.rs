//! A minimal CBOR (RFC 8949) encoder for the few structures an authenticator
//! emits: COSE keys and attestation objects.
//!
//! Output follows the CTAP2 canonical form: definite lengths, the shortest
//! integer/length encoding, and map keys sorted by their encoded bytes
//! (shorter first, then bytewise), which is also RFC 8949 §4.2.1 "core
//! deterministic encoding" for the key types used here.

/// A CBOR data item (only the major types an authenticator needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Any integer; encoded as major type 0 (>= 0) or 1 (< 0).
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries are re-ordered canonically when encoded.
    Map(Vec<(Value, Value)>),
    Bool(bool),
}

impl Value {
    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    /// Encodes this item canonically.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(n) if *n >= 0 => head(out, 0, *n as u64),
            // -1 - n, computed without overflow for i64::MIN.
            Value::Int(n) => head(out, 1, !(*n) as u64),
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.encode(out);
                }
            }
            Value::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();
                encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
                encoded.dedup_by(|a, b| a.0 == b.0);
                head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
        }
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::Value;
    use super::Value::*;

    #[test]
    fn rfc8949_appendix_a_vectors() {
        assert_eq!(Int(0).to_vec(), [0x00]);
        assert_eq!(Int(23).to_vec(), [0x17]);
        assert_eq!(Int(24).to_vec(), [0x18, 0x18]);
        assert_eq!(Int(1000).to_vec(), [0x19, 0x03, 0xe8]);
        assert_eq!(Int(1_000_000).to_vec(), [0x1a, 0x00, 0x0f, 0x42, 0x40]);
        assert_eq!(
            Int(1_000_000_000_000).to_vec(),
            [0x1b, 0, 0, 0, 0xe8, 0xd4, 0xa5, 0x10, 0x00]
        );
        assert_eq!(Int(-1).to_vec(), [0x20]);
        assert_eq!(Int(-100).to_vec(), [0x38, 0x63]);
        assert_eq!(Int(-1000).to_vec(), [0x39, 0x03, 0xe7]);
        assert_eq!(
            Int(i64::MIN).to_vec(),
            [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(Bytes(vec![1, 2, 3, 4]).to_vec(), [0x44, 1, 2, 3, 4]);
        assert_eq!(Value::text("IETF").to_vec(), [0x64, b'I', b'E', b'T', b'F']);
        assert_eq!(
            Array(vec![Int(1), Int(2), Int(3)]).to_vec(),
            [0x83, 1, 2, 3]
        );
        assert_eq!(Map(vec![]).to_vec(), [0xa0]);
        assert_eq!(Bool(true).to_vec(), [0xf5]);
        assert_eq!(
            Map(vec![(Int(2), Int(4)), (Int(1), Int(2))]).to_vec(),
            [0xa2, 0x01, 0x02, 0x02, 0x04]
        );
    }

    #[test]
    fn canonical_key_order() {
        // CTAP2: shorter encodings first, then bytewise.
        let m = Map(vec![
            (Value::text("authData"), Int(0)),
            (Int(-3), Int(0)),
            (Value::text("fmt"), Int(0)),
            (Int(3), Int(0)),
            (Int(-1), Int(0)),
            (Int(1), Int(0)),
            (Value::text("attStmt"), Int(0)),
        ]);
        let enc = m.to_vec();
        let keys_in_order = [
            &[0x01][..],
            &[0x03],
            &[0x20],
            &[0x22],
            &[0x63, b'f', b'm', b't'],
            b"\x67attStmt",
            b"\x68authData",
        ];
        let mut pos = 1;
        for k in keys_in_order {
            assert_eq!(&enc[pos..pos + k.len()], k);
            pos += k.len() + 1;
        }
        assert_eq!(pos, enc.len());
    }
}
