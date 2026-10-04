mod common;

use npw_export::csv_export::COLUMNS;
use npw_export::export_csv;
use serde_json::Value;

fn rows() -> (Vec<u8>, Vec<csv::StringRecord>) {
    let bytes = export_csv(&common::vaults());
    let body = bytes
        .strip_prefix(b"\xEF\xBB\xBF".as_slice())
        .expect("UTF-8 BOM");
    let mut r = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(body);
    assert_eq!(r.headers().unwrap().iter().collect::<Vec<_>>(), COLUMNS);
    let rows = r.records().map(Result::unwrap).collect();
    (bytes, rows)
}

#[test]
fn layout() {
    let (bytes, rows) = rows();
    let text = std::str::from_utf8(&bytes[3..]).unwrap();
    assert!(
        text.starts_with("vault,title,username,password,url,totp,notes,tags,template,fields\r\n")
    );
    assert!(text.ends_with("\r\n"));
    // one row per non-deleted item
    let vaults = common::vaults();
    let expected: usize = vaults
        .iter()
        .map(|v| v.items.iter().filter(|i| !i.deleted).count())
        .sum();
    assert_eq!(rows.len(), expected);
    assert!(rows.iter().all(|r| &r[1] != "已删除的笔记"));
}

#[test]
fn login_row() {
    let (_, rows) = rows();
    let r = rows.iter().find(|r| &r[1] == common::LOGIN_TITLE).unwrap();
    assert_eq!(&r[0], "个人");
    assert_eq!(&r[2], "user@example.com");
    assert_eq!(&r[3], common::PASSWORD);
    assert_eq!(&r[4], "https://example.com/login");
    assert_eq!(&r[5], common::TOTP_SECRET);
    assert_eq!(&r[6], common::NOTES);
    assert_eq!(&r[7], "工作/开发;a;b");
    assert_eq!(&r[8], "login");
    let fields: Vec<Value> = serde_json::from_str(&r[9]).unwrap();
    let rec = fields.iter().find(|f| f["label"] == "恢复码").unwrap();
    assert_eq!(rec["section"], "恢复");
    assert_eq!(rec["kind"], "concealed");
    assert_eq!(rec["value"], common::RECOVERY);
    assert!(fields
        .iter()
        .any(|f| f["value"] == "https://accounts.example.com"));
    assert!(fields
        .iter()
        .any(|f| f["value"] == "androidapp://com.example.app"));
    assert!(
        fields.iter().all(|f| f["label"] != "空字段"),
        "empty fields skipped"
    );
}

#[test]
fn template_rows_keep_their_fields() {
    let (_, rows) = rows();
    for item in common::template_items() {
        let c = &item.content;
        let r = rows.iter().find(|r| &r[1] == c.title.as_str()).unwrap();
        assert_eq!(&r[8], c.template.as_str());
        let fields: Vec<Value> = if r[9].is_empty() {
            vec![]
        } else {
            serde_json::from_str(&r[9]).unwrap()
        };
        for f in &c.fields {
            let in_column = [&r[2], &r[3], &r[5]].contains(&f.text().as_str());
            let in_json = fields.iter().any(|j| j["value"] == f.value);
            assert!(in_column || in_json, "{}: {} missing", c.title, f.id);
        }
    }
}
