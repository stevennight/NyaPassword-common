//! Three-way merge of item content (design doc §7.4).
//!
//! `base` is the last version both sides agreed on, `local` is this device's
//! unsynced edit, `remote` is the server's newer revision. The merge works on
//! the JSON tree:
//!
//! - a value changed on one side only takes that side;
//! - objects merge key by key;
//! - ID-keyed arrays (fields, sections, URLs, passkeys, attachments, history,
//!   conflicts) merge element by element; additions on both sides are kept;
//! - tags merge as a set; notes merge line by line;
//! - deleted on one side but edited on the other: the edit wins;
//! - changed differently on both sides: the remote value is kept and the local
//!   value is recorded in `conflicts` for the user to resolve.
//!
//! Nothing a user typed is ever dropped: every value either ends up in the
//! result, in `conflicts`, or (for older values) in the revision history.

use serde_json::{Map, Value};

use crate::format::parse_version;
use crate::{new_short_id, now_ms, Conflict, ItemContent};

const KEYED_ARRAYS: &[&str] = &[
    "fields",
    "sections",
    "urls",
    "passkeys",
    "attachments",
    "history",
    "conflicts",
];
const SET_ARRAYS: &[&str] = &["tags"];

pub struct MergeOutcome {
    pub content: ItemContent,
    /// Conflicts recorded by this merge (also present in `content.conflicts`).
    pub new_conflicts: usize,
}

struct Ctx<'a> {
    conflicts: Vec<Conflict>,
    device: &'a str,
    now: i64,
    local: &'a Value,
    remote: &'a Value,
}

impl Ctx<'_> {
    fn conflict(&mut self, path: &[String], local: Value, kept: Value) {
        let label = self.label_for(path);
        self.conflicts.push(Conflict {
            id: new_short_id("c"),
            path: path.join("/"),
            label,
            value: local,
            kept,
            device: self.device.to_string(),
            at: self.now,
            extra: Map::new(),
        });
    }

    /// The field's label for `fields/<id>/...` paths, empty otherwise (the UI names those).
    fn label_for(&self, path: &[String]) -> String {
        if path.len() >= 2 && path[0] == "fields" {
            for side in [self.remote, self.local] {
                if let Some(arr) = side.get("fields").and_then(Value::as_array) {
                    if let Some(f) = arr
                        .iter()
                        .find(|f| f.get("id").and_then(Value::as_str) == Some(&path[1]))
                    {
                        if let Some(l) = f.get("label").and_then(Value::as_str) {
                            return l.to_string();
                        }
                    }
                }
            }
        }
        String::new()
    }
}

pub fn merge_items(
    base: Option<&ItemContent>,
    local: &ItemContent,
    remote: &ItemContent,
    device: &str,
) -> MergeOutcome {
    let b = base.map(|b| serde_json::to_value(b).expect("serializable"));
    let l = serde_json::to_value(local).expect("serializable");
    let r = serde_json::to_value(remote).expect("serializable");
    let mut ctx = Ctx {
        conflicts: vec![],
        device,
        now: now_ms(),
        local: &l,
        remote: &r,
    };
    let merged =
        merge_value(b.as_ref(), Some(&l), Some(&r), &mut vec![], &mut ctx).unwrap_or(Value::Null);
    let new_conflicts = ctx.conflicts.len();
    let conflicts = std::mem::take(&mut ctx.conflicts);

    match serde_json::from_value::<ItemContent>(merged) {
        Ok(mut content) => {
            content.conflicts.extend(conflicts);
            MergeOutcome {
                content,
                new_conflicts,
            }
        }
        Err(_) => {
            // The merged tree no longer fits the schema (cannot happen with
            // well-formed inputs). Keep the remote item and the whole local one
            // as a conflict, so still nothing is lost.
            let mut content = remote.clone();
            content.conflicts.push(Conflict {
                id: new_short_id("c"),
                path: String::new(),
                label: String::new(),
                value: l.clone(),
                kept: Value::Null,
                device: device.to_string(),
                at: now_ms(),
                extra: Map::new(),
            });
            MergeOutcome {
                content,
                new_conflicts: 1,
            }
        }
    }
}

fn merge_value(
    base: Option<&Value>,
    local: Option<&Value>,
    remote: Option<&Value>,
    path: &mut Vec<String>,
    ctx: &mut Ctx,
) -> Option<Value> {
    if local == remote {
        return local.cloned();
    }
    if local == base {
        return remote.cloned();
    }
    if remote == base {
        return local.cloned();
    }
    // Both sides changed, differently.
    let (l, r) = match (local, remote) {
        (None, Some(r)) => return Some(r.clone()), // deleted here, edited there: the edit wins
        (Some(l), None) => return Some(l.clone()),
        (Some(l), Some(r)) => (l, r),
        (None, None) => return None,
    };

    let top = if path.len() == 1 {
        Some(path[0].as_str())
    } else {
        None
    };
    match top {
        Some("updated_at") => return Some(max_num(l, r)),
        Some("created_at") => return Some(min_num(l, r)),
        Some("format") => return Some(max_version(l, r)),
        _ => {}
    }

    match (l, r) {
        (Value::Object(lo), Value::Object(ro)) => {
            let bo = base.and_then(Value::as_object);
            Some(Value::Object(merge_objects(bo, lo, ro, path, ctx)))
        }
        (Value::Array(la), Value::Array(ra))
            if top.is_some_and(|t| KEYED_ARRAYS.contains(&t)) && all_keyed(la) && all_keyed(ra) =>
        {
            let ba = base.and_then(Value::as_array).filter(|a| all_keyed(a));
            Some(Value::Array(merge_keyed(ba, la, ra, path, ctx)))
        }
        (Value::Array(la), Value::Array(ra)) if top.is_some_and(|t| SET_ARRAYS.contains(&t)) => {
            let ba = base.and_then(Value::as_array);
            Some(Value::Array(merge_set(ba, la, ra)))
        }
        (Value::String(ls), Value::String(rs)) if top == Some("notes") => {
            let bs = base.and_then(Value::as_str).unwrap_or("");
            match diffy::merge(bs, ls, rs) {
                Ok(merged) => Some(Value::String(merged)),
                Err(_) => {
                    ctx.conflict(path, l.clone(), r.clone());
                    Some(r.clone())
                }
            }
        }
        _ => {
            ctx.conflict(path, l.clone(), r.clone());
            Some(r.clone())
        }
    }
}

fn merge_objects(
    base: Option<&Map<String, Value>>,
    l: &Map<String, Value>,
    r: &Map<String, Value>,
    path: &mut Vec<String>,
    ctx: &mut Ctx,
) -> Map<String, Value> {
    let mut keys: Vec<&String> = r.keys().collect();
    for k in l.keys() {
        if !r.contains_key(k) {
            keys.push(k);
        }
    }
    if let Some(b) = base {
        for k in b.keys() {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    let mut out = Map::new();
    for k in keys {
        path.push(k.clone());
        let v = merge_value(base.and_then(|b| b.get(k)), l.get(k), r.get(k), path, ctx);
        path.pop();
        if let Some(v) = v {
            out.insert(k.clone(), v);
        }
    }
    out
}

fn id_of(v: &Value) -> Option<&str> {
    v.get("id").and_then(Value::as_str)
}

fn all_keyed(a: &[Value]) -> bool {
    let mut seen = std::collections::HashSet::new();
    a.iter().all(|v| id_of(v).is_some_and(|id| seen.insert(id)))
}

fn find<'a>(a: &'a [Value], id: &str) -> Option<&'a Value> {
    a.iter().find(|v| id_of(v) == Some(id))
}

fn merge_keyed(
    base: Option<&Vec<Value>>,
    l: &[Value],
    r: &[Value],
    path: &mut Vec<String>,
    ctx: &mut Ctx,
) -> Vec<Value> {
    let mut ids: Vec<&str> = r.iter().filter_map(id_of).collect();
    for v in l {
        let id = id_of(v).expect("checked by all_keyed");
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        path.push(id.to_string());
        let merged = merge_value(
            base.and_then(|b| find(b, id)),
            find(l, id),
            find(r, id),
            path,
            ctx,
        );
        path.pop();
        if let Some(v) = merged {
            out.push(v);
        }
    }
    out
}

fn merge_set(base: Option<&Vec<Value>>, l: &[Value], r: &[Value]) -> Vec<Value> {
    let empty = vec![];
    let b = base.unwrap_or(&empty);
    let mut out = vec![];
    for v in r.iter().chain(l.iter()) {
        if out.contains(v) {
            continue;
        }
        let (in_b, in_l, in_r) = (b.contains(v), l.contains(v), r.contains(v));
        // kept when both have it, or when one side added it; dropped when one side removed it
        if (in_l && in_r) || (!in_b && (in_l || in_r)) {
            out.push(v.clone());
        }
    }
    out
}

fn max_num(a: &Value, b: &Value) -> Value {
    if a.as_i64().unwrap_or(i64::MIN) >= b.as_i64().unwrap_or(i64::MIN) {
        a.clone()
    } else {
        b.clone()
    }
}

fn min_num(a: &Value, b: &Value) -> Value {
    if a.as_i64().unwrap_or(i64::MAX) <= b.as_i64().unwrap_or(i64::MAX) {
        a.clone()
    } else {
        b.clone()
    }
}

fn max_version(a: &Value, b: &Value) -> Value {
    let va = a.as_str().and_then(parse_version);
    let vb = b.as_str().and_then(parse_version);
    if va >= vb {
        a.clone()
    } else {
        b.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{kind, purpose};
    use crate::{Field, UrlEntry};

    fn login() -> ItemContent {
        let mut c = ItemContent::new("login", "GitHub");
        c.fields.push(
            Field::new("username", "用户名", kind::TEXT)
                .with_purpose(purpose::USERNAME)
                .with_value("octocat"),
        );
        c.fields.push(
            Field::new("password", "密码", kind::CONCEALED)
                .with_purpose(purpose::PASSWORD)
                .with_value("p0"),
        );
        c.tags = vec!["work".into()];
        c.notes = "line 1\nline 2\nline 3\n".into();
        c
    }

    #[test]
    fn disjoint_edits_merge_cleanly() {
        let base = login();
        let mut l = base.clone();
        l.field_mut("username").unwrap().value = "octo2".into();
        l.tags.push("dev".into());
        l.notes = "line 1 changed\nline 2\nline 3\n".into();
        let mut r = base.clone();
        r.field_mut("password").unwrap().value = "p1".into();
        r.tags.retain(|t| t != "work");
        r.tags.push("home".into());
        r.urls.push(UrlEntry::new("https://github.com"));
        r.notes = "line 1\nline 2\nline 3 changed\n".into();
        let m = merge_items(Some(&base), &l, &r, "dev-a");
        assert_eq!(m.new_conflicts, 0);
        let c = m.content;
        assert_eq!(c.field("username").unwrap().value, "octo2");
        assert_eq!(c.field("password").unwrap().value, "p1");
        assert_eq!(c.tags, vec!["home".to_string(), "dev".to_string()]);
        assert_eq!(c.urls.len(), 1);
        assert_eq!(c.notes, "line 1 changed\nline 2\nline 3 changed\n");
    }

    #[test]
    fn same_field_conflict_keeps_both_values() {
        let base = login();
        let mut l = base.clone();
        l.field_mut("password").unwrap().value = "local".into();
        let mut r = base.clone();
        r.field_mut("password").unwrap().value = "remote".into();
        let m = merge_items(Some(&base), &l, &r, "dev-a");
        assert_eq!(m.new_conflicts, 1);
        assert_eq!(m.content.field("password").unwrap().value, "remote");
        let cf = &m.content.conflicts[0];
        assert_eq!(cf.path, "fields/password/value");
        assert_eq!(cf.label, "密码");
        assert_eq!(cf.value, "local");
        assert_eq!(cf.kept, "remote");
    }

    #[test]
    fn delete_versus_edit_keeps_the_edit() {
        let base = login();
        let mut l = base.clone();
        l.fields.retain(|f| f.id != "password");
        let mut r = base.clone();
        r.field_mut("password").unwrap().value = "new".into();
        let m = merge_items(Some(&base), &l, &r, "d");
        assert_eq!(m.content.field("password").unwrap().value, "new");

        let m = merge_items(Some(&base), &r, &l, "d");
        assert_eq!(m.content.field("password").unwrap().value, "new");
    }

    #[test]
    fn both_add_fields_keeps_both() {
        let base = login();
        let mut l = base.clone();
        l.fields
            .push(Field::new("f_a", "A", kind::TEXT).with_value("a"));
        let mut r = base.clone();
        r.fields
            .push(Field::new("f_b", "B", kind::TEXT).with_value("b"));
        let m = merge_items(Some(&base), &l, &r, "d");
        assert!(m.content.field("f_a").is_some() && m.content.field("f_b").is_some());
        assert_eq!(m.new_conflicts, 0);
    }

    #[test]
    fn conflicting_notes_and_unknown_keys() {
        let base = login();
        let mut l = base.clone();
        l.notes = "line 1\nLOCAL\nline 3\n".into();
        l.extra.insert("future".into(), Value::from(1));
        let mut r = base.clone();
        r.notes = "line 1\nREMOTE\nline 3\n".into();
        r.extra.insert("future".into(), Value::from(2));
        let m = merge_items(Some(&base), &l, &r, "d");
        assert_eq!(m.content.notes, r.notes);
        assert_eq!(m.new_conflicts, 2);
        assert!(m
            .content
            .conflicts
            .iter()
            .any(|c| c.path == "notes" && c.value == Value::String(l.notes.clone())));
        assert!(m
            .content
            .conflicts
            .iter()
            .any(|c| c.path == "future" && c.value == 1));
    }

    #[test]
    fn timestamps_never_conflict() {
        let base = login();
        let mut l = base.clone();
        l.updated_at += 10;
        l.title = "L".into();
        let mut r = base.clone();
        r.updated_at += 20;
        r.favorite = true;
        let m = merge_items(Some(&base), &l, &r, "d");
        assert_eq!(m.new_conflicts, 0);
        assert_eq!(m.content.updated_at, base.updated_at + 20);
        assert_eq!(m.content.title, "L");
        assert!(m.content.favorite);
    }

    #[test]
    fn reprompt_merges_like_other_flags() {
        let base = login();
        // Turned on here, title changed there: both survive.
        let mut l = base.clone();
        l.reprompt = true;
        let mut r = base.clone();
        r.title = "GitHub (work)".into();
        let m = merge_items(Some(&base), &l, &r, "d");
        assert_eq!(m.new_conflicts, 0);
        assert!(m.content.reprompt);
        assert_eq!(m.content.title, "GitHub (work)");

        // Turned off on one side only: off.
        let mut on = base.clone();
        on.reprompt = true;
        let mut off = on.clone();
        off.reprompt = false;
        let mut r = on.clone();
        r.favorite = true;
        let m = merge_items(Some(&on), &off, &r, "d");
        assert_eq!(m.new_conflicts, 0);
        assert!(!m.content.reprompt);
        assert!(m.content.favorite);

        // Turned on on both sides: no conflict.
        let m = merge_items(Some(&base), &on, &on.clone(), "d");
        assert_eq!(m.new_conflicts, 0);
        assert!(m.content.reprompt);

        // No common base and only one side has it: kept (the edit wins).
        let m = merge_items(None, &on, &base, "d");
        assert!(m.content.reprompt);
        let m = merge_items(None, &base, &on, "d");
        assert!(m.content.reprompt);
    }

    #[test]
    fn no_base_still_merges() {
        let l = login();
        let mut r = login();
        r.field_mut("password").unwrap().value = "other".into();
        let m = merge_items(None, &l, &r, "d");
        assert_eq!(m.content.field("password").unwrap().value, "other");
        assert!(m.content.conflicts.iter().any(|c| c.value == "p0"));
    }
}
