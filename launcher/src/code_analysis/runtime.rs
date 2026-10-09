//! One private resolver/validation home for verify and later doctor reuse.
//! The caller supplies the already verified active release under its lease.
//! Only mapping/SBOM and the selected Cppcheck namespace are read here; this
//! does not repeat the launcher's whole-Runtime integrity scan or consult PATH.
use super::config::{identity, object, strict_json, Snapshot};
use super::*;
use crate::manifest::{ReleaseFile, ReleaseManifest};
use std::collections::{BTreeMap, BTreeSet};
use std::os::windows::fs::MetadataExt;

pub(crate) struct Program {
    pub(super) executable: PathBuf,
    pub(super) version: String,
    pub(super) fields: Value,
    snapshots: Vec<Snapshot>,
    directories: Vec<(PathBuf, config::Identity)>,
    root: PathBuf,
    namespace: BTreeSet<String>,
}
fn invalid(message: impl Into<String>) -> Problem {
    Problem::blocked(
        "executable-unavailable",
        format!("Trusted Cppcheck runtime unusable: {}", message.into()),
        "Restore the complete supported immutable Windows x86_64 runtime and relaunch.",
    )
}
fn parts(name: &str) -> Result<Vec<&str>> {
    if name.is_empty() || name.chars().any(|c| c < ' ' || r#"\<>:"|?*"#.contains(c)) {
        return Err(invalid(format!("Invalid runtime-relative path: {name}")));
    }
    let parts: Vec<_> = name.split('/').collect();
    for part in &parts {
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if part.is_empty()
            || [".", ".."].contains(part)
            || part.ends_with(['.', ' '])
            || ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && (b'1'..=b'9').contains(&stem.as_bytes()[3])
        {
            return Err(invalid(format!("Invalid Windows runtime path: {name}")));
        }
    }
    Ok(parts)
}
fn runtime_path(root: &Path, name: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for part in parts(name)? {
        path.push(part);
        let metadata = fs::symlink_metadata(&path).map_err(|e| invalid(format!("{name}: {e}")))?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid(format!(
                "Runtime reparse traversal: {}",
                path.display()
            )));
        }
    }
    let resolved = canonical(&path).map_err(|e| invalid(format!("{name}: {e}")))?;
    if !resolved.starts_with(root) {
        return Err(invalid(format!("Runtime path escapes root: {name}")));
    }
    Ok(resolved)
}
fn version_string(v: &Value) -> Result<String> {
    let value = v
        .as_str()
        .ok_or_else(|| invalid("program version must be a string"))?;
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || !p.bytes().all(|c| c.is_ascii_digit())
                || p.len() > 1 && p.starts_with('0')
        })
    {
        return Err(invalid("program version must contain three numeric parts"));
    }
    Ok(value.into())
}
fn unique_paths(value: &Value, label: &str) -> Result<Vec<String>> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid(format!("{label} must be a unique path list")))?;
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for value in values {
        let path = value
            .as_str()
            .ok_or_else(|| invalid(format!("{label} must contain strings")))?;
        parts(path)?;
        if !seen.insert(path) {
            return Err(invalid(format!("Duplicate {label}: {path}")));
        }
        paths.push(path.into());
    }
    Ok(paths)
}
fn namespace(root: &Path, budget: &Budget) -> Result<BTreeSet<String>> {
    let mut actual = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root.join("analysis/cppcheck")).follow_links(false) {
        budget.remaining()?;
        let entry = entry.map_err(|e| invalid(e.to_string()))?;
        let name = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| invalid(e.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        runtime_path(root, &name)?;
        if entry.file_type().is_file() {
            actual.insert(name);
        } else if !entry.file_type().is_dir() {
            return Err(invalid(format!(
                "Nonregular Cppcheck namespace entry: {name}"
            )));
        }
    }
    Ok(actual)
}
impl Program {
    pub(super) fn recheck(&self, budget: &Budget) -> Result<()> {
        let checked = (|| -> Result<()> {
            for snapshot in &self.snapshots {
                budget.remaining()?;
                if runtime_path(
                    &self.root,
                    &snapshot
                        .path
                        .strip_prefix(&self.root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                )? != snapshot.path
                    || identity(&snapshot.path)? != snapshot.identity
                {
                    return Err(Problem::execution(
                        "configuration-changed",
                        "Validated runtime payload changed during verification.",
                    ));
                }
            }
            for (path, before) in &self.directories {
                budget.remaining()?;
                if identity(path)? != *before {
                    return Err(Problem::execution(
                        "configuration-changed",
                        "Validated runtime directory changed during verification.",
                    ));
                }
            }
            if namespace(&self.root, budget)? != self.namespace {
                return Err(Problem::execution(
                    "configuration-changed",
                    "Validated Cppcheck namespace changed during verification.",
                ));
            }
            Ok(())
        })();
        checked.map_err(|error| {
            if error.code == "analysis/timeout" {
                error
            } else {
                Problem::execution(
                    "configuration-changed",
                    format!(
                        "Validated runtime payload changed during verification: {}",
                        error.message
                    ),
                )
            }
        })
    }
}
pub(crate) fn resolve(root: &Path, release: &ReleaseManifest, budget: &Budget) -> Result<Program> {
    let resolved = (|| -> Result<Program> {
        budget.remaining()?;
        if release.platform != "windows"
            || release.architecture != "x86_64"
            || !cfg!(target_arch = "x86_64")
        {
            return Err(invalid("Release/host target must be windows/x86_64"));
        }
        let root = canonical(root)?;
        let (manifest_snapshot, manifest_bytes) =
            Snapshot::capture(&runtime_path(&root, "release-manifest.json")?, budget)?;
        if strict_json(&manifest_bytes)? != serde_json::to_value(release)? {
            return Err(invalid(
                "Active release manifest changed after verification",
            ));
        }
        let mut inventory = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for leaf in &release.files {
            budget.remaining()?;
            parts(&leaf.path)?;
            if !seen.insert(leaf.path.to_ascii_lowercase()) {
                return Err(invalid(format!(
                    "Duplicate/case-colliding inventory path: {}",
                    leaf.path
                )));
            }
            inventory.insert(leaf.path.clone(), leaf);
        }
        let mut snapshots = vec![manifest_snapshot];
        let mut payload = |name: &str, kind: &str, executable: bool| -> Result<Vec<u8>> {
            let leaf: &&ReleaseFile = inventory
                .get(name)
                .ok_or_else(|| invalid(format!("Missing inventory payload {name}")))?;
            if leaf.kind != kind || leaf.executable != executable {
                return Err(invalid(format!("Misclassified inventory payload: {name}")));
            }
            let path = runtime_path(&root, name)?;
            if !path.is_file() {
                return Err(invalid(format!(
                    "Required payload must be a regular file: {name}"
                )));
            }
            let (snapshot, bytes) = Snapshot::capture(&path, budget)?;
            if bytes.len() as u64 != leaf.size || snapshot.hash != leaf.sha256 {
                return Err(invalid(format!(
                    "Payload size/hash/identity mismatch: {name}"
                )));
            }
            snapshots.push(snapshot);
            Ok(bytes)
        };
        let mapping_bytes = payload("analysis/runtime.json", "metadata", false)?;
        let mapping = strict_json(&mapping_bytes)?;
        object(
            &mapping,
            "analysis/runtime.json",
            &["schema_version", "platform", "architecture", "programs"],
            &["schema_version", "platform", "architecture", "programs"],
        )?;
        if mapping["schema_version"].as_u64() != Some(1)
            || mapping["platform"] != "windows"
            || mapping["architecture"] != "x86_64"
        {
            return Err(invalid(
                "Unsupported mapping schema_version/platform/architecture",
            ));
        }
        object(
            &mapping["programs"],
            "programs",
            &["cppcheck", "clangd"],
            &["cppcheck", "clangd"],
        )?;
        let mut cpp_licenses = Vec::new();
        let mut cpp_dependencies = Vec::new();
        let mut cpp_version = String::new();
        for name in ["cppcheck", "clangd"] {
            let program = &mapping["programs"][name];
            let mut fields = vec![
                "version",
                "executable",
                "licenses",
                "dependencies",
                "sbom_ref",
            ];
            if name == "cppcheck" {
                fields.extend(["cfg_dir", "platforms_dir"]);
            } else {
                fields.push("resource_dir");
            }
            object(program, &format!("programs.{name}"), &fields, &fields)?;
            let version = version_string(&program["version"])?;
            let expected_exe = if name == "cppcheck" {
                "analysis/cppcheck/cppcheck.exe"
            } else {
                "analysis/clangd/bin/clangd.exe"
            };
            if program["executable"] != expected_exe
                || program["sbom_ref"] != format!("byo-analysis:{name}")
            {
                return Err(invalid(format!(
                    "programs.{name} executable/sbom_ref mismatch"
                )));
            }
            let required: Vec<_> = if name == "cppcheck" {
                if program["cfg_dir"] != "analysis/cppcheck/cfg"
                    || program["platforms_dir"] != "analysis/cppcheck/platforms"
                {
                    return Err(invalid("programs.cppcheck cfg_dir/platforms_dir mismatch"));
                }
                [
                    "COPYING",
                    "simplecpp-LICENSE",
                    "tinyxml2-LICENSE",
                    "picojson-LICENSE",
                ]
                .iter()
                .map(|name| format!("analysis/cppcheck/licenses/{name}"))
                .collect()
            } else {
                if program["resource_dir"]
                    != format!(
                        "analysis/clangd/lib/clang/{}",
                        version.split('.').next().unwrap()
                    )
                {
                    return Err(invalid(
                        "programs.clangd.resource_dir major/version mismatch",
                    ));
                }
                vec!["analysis/clangd/LICENSE.TXT".into()]
            };
            let licenses =
                unique_paths(&program["licenses"], &format!("programs.{name}.licenses"))?;
            if required.iter().any(|path| !licenses.contains(path))
                || licenses.iter().any(|path| {
                    !required.contains(path)
                        && !path.starts_with(&format!("analysis/{name}/licenses/"))
                })
            {
                return Err(invalid(format!(
                    "programs.{name}.licenses missing/misplaced notice"
                )));
            }
            let dependencies = unique_paths(
                &program["dependencies"],
                &format!("programs.{name}.dependencies"),
            )?;
            let prefix = if name == "cppcheck" {
                "analysis/cppcheck/"
            } else {
                "analysis/clangd/bin/"
            };
            if dependencies.iter().any(|path| {
                !path
                    .strip_prefix(prefix)
                    .is_some_and(|leaf| !leaf.contains('/') && leaf.ends_with(".dll"))
            }) {
                return Err(invalid(format!(
                    "programs.{name}.dependencies must be adjacent DLLs"
                )));
            }
            if name == "cppcheck" {
                cpp_licenses = licenses;
                cpp_dependencies = dependencies;
                cpp_version = version;
            }
        }
        let sbom = strict_json(&payload("sbom.cdx.json", "metadata", false)?)?;
        let components = sbom["components"]
            .as_array()
            .ok_or_else(|| invalid("SBOM components missing"))?;
        let applications: Vec<_> = components
            .iter()
            .filter(|c| c["bom-ref"] == "byo-analysis:cppcheck")
            .collect();
        if applications.len() != 1 {
            return Err(invalid(
                "Cppcheck SBOM application identity missing/duplicated",
            ));
        }
        let app = applications[0];
        if app["type"] != "application"
            || app["name"] != "cppcheck"
            || app["version"] != cpp_version
            || !app["licenses"].as_array().is_some_and(|a| !a.is_empty())
        {
            return Err(invalid(
                "Cppcheck SBOM application name/version/licenses mismatch",
            ));
        }
        for property in ["byo:analysis:upstream", "byo:analysis:recipe"] {
            if !app["properties"].as_array().is_some_and(|a| {
                a.iter().any(|p| {
                    p["name"] == property
                        && p["value"].as_str().is_some_and(|s| !s.trim().is_empty())
                })
            }) {
                return Err(invalid(format!(
                    "Cppcheck SBOM provenance missing: {property}"
                )));
            }
        }
        let namespace_expected: BTreeSet<_> = inventory
            .keys()
            .filter(|p| p.starts_with("analysis/cppcheck/"))
            .cloned()
            .collect();
        let mut expected_leaves: BTreeSet<_> = cpp_licenses
            .iter()
            .chain(cpp_dependencies.iter())
            .cloned()
            .collect();
        expected_leaves.insert("analysis/cppcheck/cppcheck.exe".into());
        let mut directories = Vec::new();
        for (dir, suffix) in [
            ("analysis/cppcheck/cfg", ".cfg"),
            ("analysis/cppcheck/platforms", ".xml"),
        ] {
            let prefix = format!("{dir}/");
            let leaves: Vec<_> = namespace_expected
                .iter()
                .filter(|name| {
                    name.strip_prefix(&prefix)
                        .is_some_and(|leaf| !leaf.contains('/') && leaf.ends_with(suffix))
                })
                .cloned()
                .collect();
            if leaves.is_empty() {
                return Err(invalid(format!("Empty required data directory: {dir}")));
            }
            expected_leaves.extend(leaves);
            let path = runtime_path(&root, dir)?;
            directories.push((path.clone(), identity(&path)?));
        }
        if !expected_leaves.contains("analysis/cppcheck/cfg/std.cfg")
            || namespace_expected != expected_leaves
            || namespace(&root, budget)? != namespace_expected
        {
            return Err(invalid(
                "Missing cfg/std.cfg or unapproved Cppcheck namespace payload",
            ));
        }
        let links = sbom["dependencies"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["ref"] == "byo-analysis:cppcheck"))
            .and_then(|d| d["dependsOn"].as_array())
            .ok_or_else(|| invalid("Cppcheck SBOM dependencies missing"))?;
        for name in &namespace_expected {
            let kind = if name == "analysis/cppcheck/cppcheck.exe" {
                "analysis-executable"
            } else if cpp_licenses.contains(name) {
                "license"
            } else if cpp_dependencies.contains(name) {
                "analysis-dependency"
            } else {
                "analysis-data"
            };
            let bytes = payload(name, kind, kind == "analysis-executable")?;
            let digest = &inventory[name].sha256;
            if !components.iter().any(|c| {
                c["name"] == *name
                    && links.contains(&c["bom-ref"])
                    && c["hashes"].as_array().is_some_and(|h| {
                        h.iter()
                            .any(|h| h["alg"] == "SHA-256" && h["content"] == *digest)
                    })
            }) {
                return Err(invalid(format!(
                    "Cppcheck payload SBOM relationship/hash missing: {name}"
                )));
            }
            if ["analysis-executable", "analysis-dependency"].contains(&kind) {
                let offset = bytes
                    .get(60..64)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
                    .unwrap_or(usize::MAX);
                if bytes.get(..2) != Some(b"MZ")
                    || offset.checked_add(26).is_none_or(|end| end > bytes.len())
                    || bytes.get(offset..offset.saturating_add(4)) != Some(b"PE\0\0")
                    || bytes.get(offset.saturating_add(4)..offset.saturating_add(6))
                        != Some(&[0x64, 0x86])
                    || bytes.get(offset.saturating_add(24)..offset.saturating_add(26))
                        != Some(&[0x0b, 0x02])
                {
                    return Err(invalid(format!(
                        "Payload is not AMD64 PE32+ native: {name}"
                    )));
                }
            }
        }
        let fields = json!({"executable":root.join("analysis/cppcheck/cppcheck.exe"),"executable_origin":"managed_runtime","executable_sha256":inventory["analysis/cppcheck/cppcheck.exe"].sha256,"runtime_root":root,"runtime_manifest_sha256":crate::manifest::sha256_bytes(&manifest_bytes),"analysis_mapping_sha256":crate::manifest::sha256_bytes(&mapping_bytes),"data_paths":{"cfg_dir":root.join("analysis/cppcheck/cfg"),"platforms_dir":root.join("analysis/cppcheck/platforms")}});
        Ok(Program {
            executable: root.join("analysis/cppcheck/cppcheck.exe"),
            version: cpp_version,
            fields,
            snapshots,
            directories,
            root,
            namespace: namespace_expected,
        })
    })();
    resolved.map_err(|error| {
        if ["analysis/timeout", "analysis/executable-unavailable"].contains(&error.code.as_str()) {
            error
        } else {
            invalid(error.message)
        }
    })
}
