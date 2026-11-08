use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

const FALLBACK_VERSION_CODE: &str = "1";
const MAX_VERSION_CODE: u64 = 2_100_000_000;
const MAX_VERSION_NAME_LENGTH: usize = 64;

fn main() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    emit_build_version(&project_root).expect("failed to derive the desktop build version");
    stage_development_runtime().expect("failed to stage the development runtime");

    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .embed_resources(slint_build::EmbedResourcesKind::EmbedFiles);
    slint_build::compile_with_config("ui/app-window.slint", config)
        .expect("failed to compile Slint UI");
}

fn emit_build_version(project_root: &Path) -> io::Result<()> {
    for name in [
        "TOPNODE_VERSION_CODE",
        "TOPNODE_VERSION_NAME",
        "TOPNODE_GIT_COMMIT",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let version_code_override = non_empty_environment("TOPNODE_VERSION_CODE");
    let version_name_override = non_empty_environment("TOPNODE_VERSION_NAME");
    let commit_override = non_empty_environment("TOPNODE_GIT_COMMIT");
    let has_git_metadata = git_output(project_root, ["rev-parse", "--is-inside-work-tree"])
        .is_ok_and(|value| value == "true");

    if has_git_metadata {
        emit_git_rerun_paths(project_root);
        if (version_code_override.is_none() || version_name_override.is_none())
            && git_output(project_root, ["rev-parse", "--is-shallow-repository"])? == "true"
        {
            return Err(io::Error::other(
                "automatic desktop versioning requires complete Git history; fetch with \
                 --unshallow or set TOPNODE_VERSION_CODE and TOPNODE_VERSION_NAME",
            ));
        }
    }

    let version_code = match version_code_override {
        Some(value) => value,
        None if has_git_metadata => git_output(project_root, ["rev-list", "--count", "HEAD"])?,
        None => FALLBACK_VERSION_CODE.to_owned(),
    };
    let version_code = version_code
        .parse::<u64>()
        .map_err(|_| io::Error::other("TOPNODE_VERSION_CODE must be a positive decimal integer"))?;
    if !(1..=MAX_VERSION_CODE).contains(&version_code) {
        return Err(io::Error::other(format!(
            "TOPNODE_VERSION_CODE must be between 1 and {MAX_VERSION_CODE}"
        )));
    }

    let discovered_commit = has_git_metadata
        .then(|| git_output(project_root, ["rev-parse", "HEAD"]))
        .transpose()?;
    let git_commit = commit_override
        .or_else(|| discovered_commit.clone())
        .unwrap_or_else(|| "unknown".to_owned());
    if git_commit != "unknown" && !valid_git_commit(&git_commit) {
        return Err(io::Error::other(
            "TOPNODE_GIT_COMMIT must contain 40-64 hexadecimal characters",
        ));
    }

    let version_name = match version_name_override {
        Some(value) => value,
        None if has_git_metadata => {
            let commit_date = git_output(project_root, ["show", "-s", "--format=%cs", "HEAD"])?;
            if !valid_commit_date(&commit_date) {
                return Err(io::Error::other("Git commit date must use YYYY-MM-DD"));
            }
            let full_commit = discovered_commit.ok_or_else(|| {
                io::Error::other("Git metadata disappeared while deriving the desktop version")
            })?;
            format!("{}-{}", commit_date.replace('-', "."), &full_commit[..8])
        }
        None => env!("CARGO_PKG_VERSION").to_owned(),
    };
    if !valid_version_name(&version_name) {
        return Err(io::Error::other(format!(
            "TOPNODE_VERSION_NAME must be 1-{MAX_VERSION_NAME_LENGTH} URL-safe characters"
        )));
    }

    let build_target = env::var("TARGET")
        .map_err(|_| io::Error::other("Cargo did not provide the desktop build target"))?;
    println!("cargo:rustc-env=TOPNODE_VERSION_CODE={version_code}");
    println!("cargo:rustc-env=TOPNODE_VERSION_NAME={version_name}");
    println!("cargo:rustc-env=TOPNODE_GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=TOPNODE_BUILD_TARGET={build_target}");
    Ok(())
}

fn non_empty_environment(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn git_output<const N: usize>(project_root: &Path, arguments: [&str; N]) -> io::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project_root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "Git command failed while deriving the build version",
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(io::Error::other)
}

fn emit_git_rerun_paths(project_root: &Path) {
    emit_git_rerun_path(project_root, "HEAD");
    emit_git_rerun_path(project_root, "packed-refs");
    if let Ok(reference) = git_output(project_root, ["symbolic-ref", "-q", "HEAD"]) {
        emit_git_rerun_path(project_root, &reference);
    }
}

fn emit_git_rerun_path(project_root: &Path, git_path: &str) {
    if let Ok(path) = git_output(
        project_root,
        [
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            git_path,
        ],
    ) {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn valid_git_commit(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_commit_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn valid_version_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.len() <= MAX_VERSION_NAME_LENGTH
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn stage_development_runtime() -> io::Result<()> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let startup_source = project_root.join("config/startup.json");
    println!("cargo:rerun-if-changed={}", startup_source.display());

    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?;
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .ok_or_else(|| io::Error::other("unable to resolve Cargo profile directory"))?;
    let runtime_destination = profile_dir.join("runtime");
    fs::create_dir_all(&runtime_destination)?;
    fs::copy(&startup_source, runtime_destination.join("startup.json"))?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let core_name = if target_os == "windows" {
        "sing-box-acp.exe"
    } else {
        "sing-box-acp"
    };
    let core_source = project_root.join("runtime/core").join(core_name);
    println!("cargo:rerun-if-changed={}", core_source.display());
    if !core_source.is_file() {
        println!(
            "cargo:warning=development core not staged: expected {}",
            core_source.display()
        );
        return Ok(());
    }

    let core_destination = runtime_destination.join("core");
    fs::create_dir_all(&core_destination)?;

    fs::copy(core_source, core_destination.join(core_name))?;

    Ok(())
}
