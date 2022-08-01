use pkcs11::Ctx;
use serial_test::serial;
use std::path::PathBuf;

fn pkcs11_module_name() -> PathBuf {
    let path =
        std::env::var_os("PKCS11_MODULE").unwrap_or_else(|| "/usr/lib/libsofthsm2.so".into());
    let path_buf = PathBuf::from(path);
    if !path_buf.exists() {
        panic!("Set location of PKCS#11 module with `PKCS11_MODULE` environment variable");
    }
    path_buf
}

#[test]
#[serial]
fn new_then_initialize() {
    let mut session = Ctx::new(pkcs11_module_name()).unwrap();
    let res = session.initialize(None);
    assert!(
        res.is_ok(),
        "failed to initialize session: {}",
        res.unwrap_err()
    );
    assert!(
        session.is_initialized(),
        "internal state is not initialized"
    );
}

#[test]
#[serial]
fn new_and_initialize() {
    let result = Ctx::new_and_initialize(pkcs11_module_name());
    assert!(
        result.is_ok(),
        "failed to create or initialize new context: {}",
        result.unwrap_err()
    );
}

#[test]
fn construct_uri() {
    use crate::*;

    let uri_str_expected = "pkcs11:library-version=3;token=The%20Software%20PKCS%2311%20Softtoken;id=%69%95%3E%5C%F4%BD%EC%91;object=my-signing-key;type=private;slot-id=327;serial=DECC0401648?pin-source=file:/etc/token";

    let uri = Pkcs11Uri {
        path_attributes: PathAttributes {
            object_label: Some("my-signing-key".to_string()),
            object_class: Some(ObjectClass::PrivateKey),
            token_serial: Some([
                68, 69, 67, 67, 48, 52, 48, 49, 54, 52, 56, 32, 32, 32, 32, 32,
            ]),
            object_id: Some(vec![105, 149, 62, 92, 244, 189, 236, 145]),
            ..Default::default()
        },
        query_attributes: QueryAttributes::default(),
        raw_uri: String::new(),
    };

    assert_eq!(uri.to_string(), uri_str_expected);
}
