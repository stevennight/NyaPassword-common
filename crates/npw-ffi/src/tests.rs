use super::*;

fn tmp_db(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("npw-ffi-test-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("replica.sqlite3").to_string_lossy().into_owned()
}

fn client(name: &str) -> Arc<NpwClient> {
    NpwClient::new(
        tmp_db(name),
        random_key(),
        "Test phone".into(),
        "0.0.0-test".into(),
        "zh-CN".into(),
    )
    .unwrap()
}

fn code(e: NpwError) -> String {
    match e {
        NpwError::Core { code, .. } => code,
    }
}

fn url(u: &str, certs: &[&str]) -> UrlEntry {
    let mut e = UrlEntry::new(u);
    e.cert_sha256 = certs.iter().map(|c| c.to_string()).collect();
    e
}

#[test]
fn cert_fingerprints_normalize() {
    assert_eq!(normalize_cert("AB:cd:01 ef"), "abcd01ef");
    assert_eq!(normalize_cert(""), "");
}

#[test]
fn app_certificates_are_enforced_only_when_pinned() {
    let pkg = "com.example.app";
    let unpinned = vec![url("androidapp://com.example.app", &[])];
    assert!(app_cert_allowed(&unpinned, pkg, &["aa".into()]));
    assert!(app_cert_allowed(&unpinned, pkg, &[]));

    let pinned = vec![
        url("https://example.com", &[]),
        url("androidapp://com.example.app", &["AA:BB"]),
    ];
    assert!(app_cert_allowed(&pinned, pkg, &["aabb".into()]));
    assert!(app_cert_allowed(
        &pinned,
        pkg,
        &["ffff".into(), "AA:BB".into()]
    ));
    assert!(!app_cert_allowed(&pinned, pkg, &["ccdd".into()]));
    assert!(!app_cert_allowed(&pinned, pkg, &[]));
    // a pin for another package does not restrict this one
    let other = vec![
        url("androidapp://org.other", &["aabb"]),
        url("androidapp://com.example.app", &[]),
    ];
    assert!(app_cert_allowed(&other, pkg, &["1234".into()]));
}

#[test]
fn linking_an_app_adds_one_entry_and_merges_certs() {
    let mut c = npw_model::template("login").unwrap().new_item("zh-CN");
    assert!(link_app_url(&mut c, "com.example.app", "AA:BB"));
    assert_eq!(c.urls.len(), 1);
    assert_eq!(c.urls[0].url, "androidapp://com.example.app");
    assert_eq!(c.urls[0].match_mode, "exact");
    assert_eq!(c.urls[0].cert_sha256, vec!["aabb".to_string()]);
    // same cert again: nothing to do
    assert!(!link_app_url(&mut c, "com.example.app", "aabb"));
    // a second signer (key rotation) is added to the same entry
    assert!(link_app_url(&mut c, "com.example.app", "ccdd"));
    assert_eq!(c.urls.len(), 1);
    assert_eq!(c.urls[0].cert_sha256.len(), 2);
}

#[test]
fn fresh_device_is_signed_out_and_locked() {
    let c = client("fresh");
    let st: serde_json::Value = serde_json::from_str(&c.lock_state().unwrap()).unwrap();
    assert_eq!(st["signed_in"], false);
    assert_eq!(st["unlocked"], false);
    assert!(!c.is_unlocked());
    assert_eq!(code(c.list_items("{}".into()).unwrap_err()), "locked");
    assert_eq!(code(c.unlock("x".into()).unwrap_err()), "not_signed_in");
    assert_eq!(
        code(
            c.autofill_candidates("https://example.com".into(), vec![])
                .unwrap_err()
        ),
        "locked"
    );
    assert_eq!(
        code(c.new_item("no-such-template".into()).unwrap_err()),
        "invalid"
    );
    let item: serde_json::Value =
        serde_json::from_str(&c.new_item("login".into()).unwrap()).unwrap();
    assert_eq!(item["template"], "login");
    assert_eq!(item["fields"][0]["label"], "用户名");
}

#[test]
fn bad_device_key_is_rejected() {
    let e = NpwClient::new(
        tmp_db("badkey"),
        vec![1, 2, 3],
        "x".into(),
        "0".into(),
        "zh-CN".into(),
    );
    assert_eq!(code(e.err().unwrap()), "invalid");
}

#[test]
fn free_functions() {
    // RFC 6238 SHA-1 secret "12345678901234567890", T = 59 s, 8 digits
    let uri = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30"
        .to_string();
    let o: serde_json::Value = serde_json::from_str(&otp_code(uri, 59).unwrap()).unwrap();
    assert_eq!(o["code"], "94287082");
    assert_eq!(o["remaining"], 1);
    assert_eq!(
        code(otp_code("not a secret!".into(), 0).unwrap_err()),
        "invalid"
    );

    let g: serde_json::Value = serde_json::from_str(&generate(String::new()).unwrap()).unwrap();
    assert_eq!(g["password"].as_str().unwrap().chars().count(), 20);
    let pin: serde_json::Value =
        serde_json::from_str(&generate(r#"{"kind":"pin","length":6}"#.into()).unwrap()).unwrap();
    assert!(pin["password"]
        .as_str()
        .unwrap()
        .chars()
        .all(|c| c.is_ascii_digit()));
    assert!(password_strength("correct horse battery staple 1984".into()) >= 3);
    assert_eq!(password_strength("123".into()), 0);

    let t: serde_json::Value = serde_json::from_str(&templates("zh-CN".into()).unwrap()).unwrap();
    assert!(t
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["id"] == "bank_account"));
    let p: serde_json::Value =
        serde_json::from_str(&field_presets("zh-CN".into()).unwrap()).unwrap();
    assert!(p
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["id"] == "recovery_codes" && x["multiline"] == true));

    assert!(new_short_id("f".into()).starts_with("f_"));
    assert_eq!(
        display_host("https://Login.Example.com:8443/x".into()),
        "login.example.com:8443"
    );
    assert_eq!(
        display_host("androidapp://com.example".into()),
        "com.example"
    );
    assert_eq!(random_key().len(), 32);
    assert_ne!(random_key(), random_key());

    assert_eq!(
        code(normalize_secret_key("A1-AAAAAA".into()).unwrap_err()),
        "crypto"
    );

    assert!(passkey_origin_allows_rp(
        "https://login.example.com".into(),
        "example.com".into()
    ));
    assert!(passkey_origin_allows_rp(
        "https://example.com".into(),
        "example.com".into()
    ));
    assert!(!passkey_origin_allows_rp(
        "https://example.com".into(),
        "other.com".into()
    ));
    assert!(!passkey_origin_allows_rp(
        "https://evil-example.com".into(),
        "example.com".into()
    ));
    assert!(!passkey_origin_allows_rp(
        "http://example.com".into(),
        "example.com".into()
    ));
    assert!(!passkey_origin_allows_rp(
        "https://a.github.io".into(),
        "github.io".into()
    ));
}

/// End to end against a running server (fresh data directory: registration
/// is only open for the first account). Run with
/// `NPW_TEST_SERVER=http://127.0.0.1:8087 cargo test -p npw-ffi -- --ignored`.
#[test]
#[ignore = "needs a running nyapassword-server (NPW_TEST_SERVER)"]
fn against_a_server() {
    let Ok(server) = std::env::var("NPW_TEST_SERVER") else {
        eprintln!("NPW_TEST_SERVER not set");
        return;
    };
    let a = client("server-a");
    let kit: serde_json::Value = serde_json::from_str(
        &a.register(
            server.clone(),
            "test@example.com".into(),
            "correct horse battery".into(),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let sk = kit["secret_key"].as_str().unwrap().to_string();
    assert_eq!(normalize_secret_key(sk.to_lowercase()).unwrap(), sk);
    let vaults: serde_json::Value = serde_json::from_str(&a.vaults().unwrap()).unwrap();
    let vault = vaults[0]["id"].as_str().unwrap().to_string();

    // unknown keys written by a "newer client" survive the round trip
    let mut item: serde_json::Value =
        serde_json::from_str(&a.new_item("login".into()).unwrap()).unwrap();
    item["title"] = "Example".into();
    item["fields"][0]["value"] = "me@example.com".into();
    item["fields"][1]["value"] = "p@ss".into();
    item["fields"][1]["future_field_key"] = serde_json::json!({"x": 1});
    item["future_top_key"] = serde_json::json!([1, 2, 3]);
    item["urls"] =
        serde_json::json!([{ "id": "u_1", "url": "https://example.com/login", "match": "domain" }]);
    let id = a.save_item(vault.clone(), None, item.to_string()).unwrap();
    let back: serde_json::Value =
        serde_json::from_str(&a.item(vault.clone(), id.clone()).unwrap()).unwrap();
    assert_eq!(
        back["content"]["future_top_key"],
        serde_json::json!([1, 2, 3])
    );
    assert_eq!(back["content"]["fields"][1]["future_field_key"]["x"], 1);

    let r: serde_json::Value = serde_json::from_str(&a.sync().unwrap()).unwrap();
    assert_eq!(r["pushed"], 1);

    // autofill: web, then an app that gets linked with its certificate
    let web: serde_json::Value = serde_json::from_str(
        &a.autofill_candidates("https://www.example.com/".into(), vec![])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(web.as_array().unwrap().len(), 1);
    let app = "androidapp://com.example.app".to_string();
    assert_eq!(
        a.autofill_candidates(app.clone(), vec!["aa".into()])
            .unwrap(),
        "[]"
    );
    assert!(a
        .link_app(
            vault.clone(),
            id.clone(),
            "com.example.app".into(),
            "AA:BB".into()
        )
        .unwrap());
    let ok: serde_json::Value = serde_json::from_str(
        &a.autofill_candidates(app.clone(), vec!["aabb".into()])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ok.as_array().unwrap().len(), 1);
    assert_eq!(
        a.autofill_candidates(app, vec!["ccdd".into()]).unwrap(),
        "[]"
    );

    // passkey: an app origin creates, then signs
    let caller = r#"{"kind":"android_app","origin":"android:apk-key-hash:qrs"}"#.to_string();
    let create = r#"{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcjE","name":"me@example.com","displayName":"Me"},
        "challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"#
        .to_string();
    let created: serde_json::Value = serde_json::from_str(
        &a.passkey_create(
            caller.clone(),
            create,
            Some(vault.clone()),
            Some(id.clone()),
            vault.clone(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(created["item_id"], id.as_str());
    assert_eq!(created["response"]["type"], "public-key");
    let get = r#"{"challenge":"Y2hhbGxlbmdlMg","rpId":"example.com"}"#.to_string();
    let cands: serde_json::Value =
        serde_json::from_str(&a.passkey_candidates(caller.clone(), get.clone()).unwrap()).unwrap();
    assert_eq!(cands.as_array().unwrap().len(), 1);
    let pk = cands[0]["passkey_id"].as_str().unwrap().to_string();
    let assertion: serde_json::Value = serde_json::from_str(
        &a.passkey_get(caller, get, vault.clone(), id.clone(), pk)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(assertion["response"]["userHandle"], "dXNlcjE");

    // quick unlock key round trip, password check
    let k = a.quick_unlock_key().unwrap();
    a.lock();
    assert!(!a.is_unlocked());
    assert_eq!(
        code(a.unlock_with_key(vec![0; 32]).unwrap_err()),
        "wrong_password"
    );
    a.unlock_with_key(k).unwrap();
    assert_eq!(
        code(a.verify_password("nope".into()).unwrap_err()),
        "wrong_password"
    );
    a.verify_password("correct horse battery".into()).unwrap();
    // user verification with the biometric key ("使用前需要验证"): no lock state change
    let k = a.quick_unlock_key().unwrap();
    a.verify_key(k.clone()).unwrap();
    assert_eq!(
        code(a.verify_key(vec![0; 32]).unwrap_err()),
        "wrong_password"
    );
    assert!(a.is_unlocked());
    a.lock();
    assert_eq!(code(a.verify_key(k.clone()).unwrap_err()), "locked");
    a.unlock_with_key(k).unwrap();

    // PIN: wrap while unlocked, then verify / unlock; wrong PINs are wrong_password
    assert_eq!(code(a.pin_wrap("123".into()).unwrap_err()), "invalid");
    let blob = a.pin_wrap("2580".into()).unwrap();
    a.verify_pin(blob.clone(), "2580".into()).unwrap();
    assert_eq!(
        code(a.verify_pin(blob.clone(), "0000".into()).unwrap_err()),
        "wrong_password"
    );
    a.lock();
    assert_eq!(
        code(a.verify_pin(blob.clone(), "2580".into()).unwrap_err()),
        "locked"
    );
    assert_eq!(
        code(a.unlock_with_pin(blob.clone(), "0000".into()).unwrap_err()),
        "wrong_password"
    );
    assert_eq!(
        code(a.unlock_with_pin("{}".into(), "2580".into()).unwrap_err()),
        "invalid"
    );
    a.unlock_with_pin(blob, "2580".into()).unwrap();
    assert!(a.is_unlocked());

    // the item flag reaches the host in every view
    let mut guarded: serde_json::Value =
        serde_json::from_str(&a.item(vault.clone(), id.clone()).unwrap()).unwrap();
    guarded["content"]["reprompt"] = true.into();
    a.save_item(
        vault.clone(),
        Some(id.clone()),
        guarded["content"].to_string(),
    )
    .unwrap();
    let listed: serde_json::Value =
        serde_json::from_str(&a.list_items("{}".into()).unwrap()).unwrap();
    assert_eq!(listed[0]["reprompt"], true);
    let web: serde_json::Value = serde_json::from_str(
        &a.autofill_candidates("https://www.example.com/".into(), vec![])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(web[0]["reprompt"], true);
    a.sync().unwrap();

    // a second device signs in with the Secret Key and sees everything
    let b = client("server-b");
    b.sign_in(
        server,
        "test@example.com".into(),
        "correct horse battery".into(),
        sk,
    )
    .unwrap();
    b.sync().unwrap();
    let items: serde_json::Value =
        serde_json::from_str(&b.list_items("{}".into()).unwrap()).unwrap();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["passkeys"], 1);
    let devices: serde_json::Value = serde_json::from_str(&b.devices().unwrap()).unwrap();
    assert_eq!(devices.as_array().unwrap().len(), 2);
    assert!(!b.events_token().unwrap().is_empty());
    b.sign_out(false).unwrap();
    a.sign_out(false).unwrap();
}
