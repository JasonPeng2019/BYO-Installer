//! Byte identities of the accepted shared corpus remain part of Rust acceptance.
use sha2::{Digest, Sha256};
use std::path::Path;
#[test]
fn all_38_shared_fixture_files_match_the_accepted_manifest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code-analysis");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let files = manifest["sha256"].as_object().unwrap();
    assert_eq!(files.len(), 37);
    for (name, expected) in files {
        let actual = hex::encode(Sha256::digest(std::fs::read(root.join(name)).unwrap()));
        assert_eq!(actual, expected.as_str().unwrap(), "{name}");
    }
    assert_eq!(
        hex::encode(Sha256::digest(
            std::fs::read(root.join("manifest.json")).unwrap()
        )),
        "f0b33c167ae62673606c03cadf58796a978aeefe78725c9e667585684c77c905"
    );
}
