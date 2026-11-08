fn main() {
    let lock = "../../config/sing-box-acp.lock";
    println!("cargo:rerun-if-changed={lock}");
    let lock = std::fs::read_to_string(lock).expect("unable to read the sing-box-acp lock");
    let version = lock
        .lines()
        .find_map(|line| line.strip_prefix("version="))
        .expect("the sing-box-acp lock must declare a version");
    println!("cargo:rustc-env=TOPNODE_SING_BOX_ACP_VERSION={version}");
}
