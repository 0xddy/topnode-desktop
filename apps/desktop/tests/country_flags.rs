use std::path::Path;

#[test]
fn every_bundled_android_country_flag_can_be_decoded() {
    let flag_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/assets/flags");
    let mut flag_count = 0;
    for entry in std::fs::read_dir(flag_directory).expect("country flag directory must exist") {
        let path = entry.expect("country flag entry must be readable").path();
        if path.extension().is_none_or(|extension| extension != "webp") {
            continue;
        }
        slint::Image::load_from_path(&path)
            .unwrap_or_else(|error| panic!("failed to decode {}: {error}", path.display()));
        flag_count += 1;
    }
    assert_eq!(
        flag_count, 249,
        "the Android country flag set is incomplete"
    );
}
