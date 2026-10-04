//! The local replica in SQLite (WAL mode). Holds only ciphertext and
//! non-secret metadata, like every [`Store`].

use std::path::Path;
use std::sync::Mutex;

use npw_core::{CoreError, LocalItem, Result, Store, StoreOp};
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

fn e(err: impl std::fmt::Display) -> CoreError {
    CoreError::Store(err.to_string())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS items (
    vault_id TEXT NOT NULL,
    item_id  TEXT NOT NULL,
    data     TEXT NOT NULL,
    PRIMARY KEY (vault_id, item_id)
);
CREATE TABLE IF NOT EXISTS blobs (k TEXT PRIMARY KEY, v BLOB NOT NULL);
"#;

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(e)?;
        }
        let conn = Connection::open(path).map_err(e)?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(e)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL").map_err(e)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(e)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(e)?;
        conn.execute_batch(SCHEMA).map_err(e)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(e)?;
        if version == 0 {
            conn.pragma_update(None, "user_version", 1).map_err(e)?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// `PRAGMA integrity_check` result ("ok" when healthy).
    pub fn integrity_check(&self) -> Result<String> {
        let c = self.conn.lock().expect("db lock");
        c.query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(e)
    }
}

fn parse(data: String) -> Result<LocalItem> {
    serde_json::from_str(&data).map_err(e)
}

impl Store for SqliteStore {
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let c = self.conn.lock().expect("db lock");
        c.query_row("SELECT v FROM meta WHERE k = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(e)
    }

    fn get_item(&self, vault_id: &str, item_id: &str) -> Result<Option<LocalItem>> {
        let c = self.conn.lock().expect("db lock");
        let data: Option<String> = c
            .query_row(
                "SELECT data FROM items WHERE vault_id = ?1 AND item_id = ?2",
                [vault_id, item_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(e)?;
        data.map(parse).transpose()
    }

    fn list_items(&self, vault_id: &str) -> Result<Vec<LocalItem>> {
        let c = self.conn.lock().expect("db lock");
        let mut st = c
            .prepare_cached("SELECT data FROM items WHERE vault_id = ?1")
            .map_err(e)?;
        let rows = st
            .query_map([vault_id], |r| r.get::<_, String>(0))
            .map_err(e)?;
        rows.map(|r| r.map_err(e).and_then(parse)).collect()
    }

    fn list_all_items(&self) -> Result<Vec<LocalItem>> {
        let c = self.conn.lock().expect("db lock");
        let mut st = c.prepare_cached("SELECT data FROM items").map_err(e)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(e)?;
        rows.map(|r| r.map_err(e).and_then(parse)).collect()
    }

    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let c = self.conn.lock().expect("db lock");
        c.query_row("SELECT v FROM blobs WHERE k = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(e)
    }

    fn apply(&self, ops: Vec<StoreOp>) -> Result<()> {
        let mut c = self.conn.lock().expect("db lock");
        let tx = c.transaction().map_err(e)?;
        for op in ops {
            match op {
                StoreOp::PutMeta(k, v) => {
                    tx.execute("INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v]).map_err(e)?;
                }
                StoreOp::DeleteMeta(k) => {
                    tx.execute("DELETE FROM meta WHERE k = ?1", [k])
                        .map_err(e)?;
                }
                StoreOp::PutItem(it) => {
                    let data = serde_json::to_string(&it).map_err(e)?;
                    tx.execute(
                        "INSERT INTO items (vault_id, item_id, data) VALUES (?1, ?2, ?3) ON CONFLICT(vault_id, item_id) DO UPDATE SET data = excluded.data",
                        params![it.vault_id, it.item_id, data],
                    )
                    .map_err(e)?;
                }
                StoreOp::DeleteItem { vault_id, item_id } => {
                    tx.execute(
                        "DELETE FROM items WHERE vault_id = ?1 AND item_id = ?2",
                        [vault_id, item_id],
                    )
                    .map_err(e)?;
                }
                StoreOp::PutBlob(k, v) => {
                    tx.execute("INSERT INTO blobs (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v]).map_err(e)?;
                }
                StoreOp::DeleteBlob(k) => {
                    tx.execute("DELETE FROM blobs WHERE k = ?1", [k])
                        .map_err(e)?;
                }
                StoreOp::ClearVault(v) => {
                    tx.execute("DELETE FROM items WHERE vault_id = ?1", [v])
                        .map_err(e)?;
                }
            }
        }
        tx.commit().map_err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use npw_core::PendingEdit;

    #[test]
    fn round_trip_and_atomicity() {
        let s = SqliteStore::in_memory().unwrap();
        let it = LocalItem {
            vault_id: "v".into(),
            item_id: "i".into(),
            server: None,
            pending: Some(PendingEdit {
                op_id: "o".into(),
                base_revision: 0,
                deleted: false,
                format_major: 1,
                wrapped_key: "w".into(),
                ciphertext: "c".into(),
                created_at: 1,
                rejected: None,
            }),
            seen: vec![],
        };
        s.apply(vec![
            StoreOp::PutMeta("a".into(), vec![1, 2]),
            StoreOp::PutItem(it.clone()),
        ])
        .unwrap();
        assert_eq!(s.get_meta("a").unwrap(), Some(vec![1, 2]));
        assert_eq!(s.get_item("v", "i").unwrap(), Some(it.clone()));
        assert_eq!(s.list_items("v").unwrap().len(), 1);
        s.apply(vec![StoreOp::ClearVault("v".into())]).unwrap();
        assert!(s.list_all_items().unwrap().is_empty());
        assert_eq!(s.integrity_check().unwrap(), "ok");
    }
}
