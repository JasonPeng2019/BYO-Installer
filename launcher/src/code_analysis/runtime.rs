//! One private resolver/validation home for verify and later doctor reuse.
//! The caller supplies the already verified active release under its lease.
//! Only mapping/SBOM and the selected analyzer namespace are read here; this
//! does not repeat the launcher's whole-Runtime integrity scan or consult PATH.
use super::config::{identity, object, strict_json, Snapshot};
use super::native_format::{executable_access, Target};
use super::*;
use crate::manifest::{ReleaseFile, ReleaseManifest};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

pub(crate) struct Program {
    pub(super) executable: PathBuf,
    pub(super) version: String,
    pub(super) fields: Value,
    mapping: Value,
    snapshots: Vec<Snapshot>,
    directories: Vec<(PathBuf, config::Identity)>,
    root: PathBuf,
    namespace: BTreeSet<String>,
    selected: &'static str,
}
pub(super) fn invalid(message: impl Into<String>) -> Problem {
    Problem::blocked(
        "executable-unavailable",
        format!("Trusted analysis runtime unusable: {}", message.into()),
        "Restore the complete supported immutable runtime matching this host and relaunch.",
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
            return Err(invalid(format!("Invalid portable runtime path: {name}")));
        }
    }
    Ok(parts)
}
fn runtime_path(root: &Path, name: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for part in parts(name)? {
        let entry = fs::read_dir(&path)
            .map_err(|e| invalid(format!("{name}: {e}")))?
            .find_map(|entry| entry.ok().filter(|entry| entry.file_name() == *part));
        if entry.is_none() {
            return Err(invalid(format!(
                "Missing exact runtime path spelling: {name}"
            )));
        }
        path.push(part);
        let metadata = fs::symlink_metadata(&path).map_err(|e| invalid(format!("{name}: {e}")))?;
        if linked(&metadata) {
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
fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
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
fn namespace(root: &Path, budget: &Budget, selected: &str) -> Result<BTreeSet<String>> {
    let mut actual = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for entry in
        walkdir::WalkDir::new(root.join(format!("analysis/{selected}"))).follow_links(false)
    {
        budget.remaining()?;
        let entry = entry.map_err(|e| invalid(e.to_string()))?;
        let name = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| invalid(e.to_string()))?
            .to_str()
            .ok_or_else(|| invalid("Runtime path is not valid Unicode"))?
            .replace('\\', "/");
        runtime_path(root, &name)?;
        if entry.file_type().is_file() {
            actual.insert(name);
        } else if entry.file_type().is_dir() {
            directories.insert(name);
        } else {
            return Err(invalid(format!(
                "Nonregular analyzer namespace entry: {name}"
            )));
        }
    }
    for directory in directories {
        budget.remaining()?;
        if !actual
            .iter()
            .any(|path| path.starts_with(&format!("{directory}/")))
        {
            return Err(invalid(format!(
                "Unselected empty analyzer directory: {directory}"
            )));
        }
    }
    Ok(actual)
}
impl Program {
    // Doctor/status expose the validated mapping and sole release inventory.
    // Keeping this accessor separate leaves selected Cppcheck verification's
    // resource boundary unchanged and does not rehash the whole runtime.
    pub(super) fn status(&self, release: &ReleaseManifest) -> Result<Value> {
        let mut programs = serde_json::Map::new();
        for name in ["cppcheck", "clangd"] {
            let program = &self.mapping["programs"][name];
            let executable = program["executable"].as_str().unwrap();
            let leaf = release
                .files
                .iter()
                .find(|leaf| leaf.path == executable)
                .ok_or_else(|| invalid(format!("Missing program inventory: {executable}")))?;
            if leaf.kind != "analysis-executable" || !leaf.executable {
                return Err(invalid(format!(
                    "Misclassified program inventory: {executable}"
                )));
            }
            let mut data_paths = serde_json::Map::new();
            for key in if name == "cppcheck" {
                vec!["cfg_dir", "platforms_dir"]
            } else {
                vec!["resource_dir"]
            } {
                data_paths.insert(
                    key.into(),
                    json!(self.root.join(program[key].as_str().unwrap())),
                );
            }
            let prefix = format!("analysis/{name}/");
            let files: Vec<_> = release
                .files
                .iter()
                .filter(|leaf| leaf.path.starts_with(&prefix))
                .collect();
            programs.insert(name.into(), json!({"version":program["version"],"executable":self.root.join(executable),"executable_origin":"managed_runtime","executable_sha256":leaf.sha256,"data_paths":data_paths,"files":files}));
        }
        Ok(
            json!({"status":"ready","runtime_root":self.root,"runtime_manifest_sha256":self.fields["runtime_manifest_sha256"],"analysis_mapping_sha256":self.fields["analysis_mapping_sha256"],"programs":programs}),
        )
    }
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
            if namespace(&self.root, budget, self.selected)? != self.namespace {
                return Err(Problem::execution(
                    "configuration-changed",
                    "Validated analyzer namespace changed during verification.",
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
    resolve_selected(root, release, budget, "cppcheck")
}
pub(super) fn resolve_selected(
    root: &Path,
    release: &ReleaseManifest,
    budget: &Budget,
    selected: &'static str,
) -> Result<Program> {
    let resolved = (|| -> Result<Program> {
        budget.remaining()?;
        let target = Target::parse(&release.platform, &release.architecture)?;
        if target != Target::host()? {
            return Err(invalid("Release target does not match the native host"));
        }
        let selected_executable = target.executable(selected);
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
            || mapping["platform"] != release.platform
            || mapping["architecture"] != release.architecture
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
        let mut selected_licenses = Vec::new();
        let mut selected_dependencies = Vec::new();
        let mut selected_version = String::new();
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
            let expected_exe = target.executable(name);
            if program["executable"] != expected_exe
                || program["sbom_ref"] != format!("byo-analysis:{name}")
            {
                return Err(invalid(format!(
                    "programs.{name} executable/sbom_ref mismatch"
                )));
            }
            let mut required: Vec<_> = if name == "cppcheck" {
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
            if name == "cppcheck" && target == Target::Linux {
                required.extend([
                    "analysis/cppcheck/licenses/GCC-COPYING3".into(),
                    "analysis/cppcheck/licenses/GCC-COPYING.RUNTIME".into(),
                ]);
            }
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
            if dependencies
                .iter()
                .any(|path| !target.dependency(name, path))
            {
                return Err(invalid(format!(
                    "programs.{name}.dependencies has an invalid private native library path"
                )));
            }
            if name == selected {
                selected_licenses = licenses;
                selected_dependencies = dependencies;
                selected_version = version;
            }
        }
        let sbom = strict_json(&payload("sbom.cdx.json", "metadata", false)?)?;
        let components = sbom["components"]
            .as_array()
            .ok_or_else(|| invalid("SBOM components missing"))?;
        let applications: Vec<_> = components
            .iter()
            .filter(|c| c["bom-ref"] == format!("byo-analysis:{selected}"))
            .collect();
        if applications.len() != 1 {
            return Err(invalid(
                "Analyzer SBOM application identity missing/duplicated",
            ));
        }
        let app = applications[0];
        if app["type"] != "application"
            || app["name"] != selected
            || app["version"] != selected_version
            || !app["licenses"].as_array().is_some_and(|a| !a.is_empty())
        {
            return Err(invalid(
                "Analyzer SBOM application name/version/licenses mismatch",
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
                    "Analyzer SBOM provenance missing: {property}"
                )));
            }
        }
        let namespace_expected: BTreeSet<_> = inventory
            .keys()
            .filter(|p| p.starts_with(&format!("analysis/{selected}/")))
            .cloned()
            .collect();
        let mut expected_leaves: BTreeSet<_> = selected_licenses
            .iter()
            .chain(selected_dependencies.iter())
            .cloned()
            .collect();
        expected_leaves.insert(selected_executable.clone());
        let mut directories = Vec::new();
        let resource = mapping["programs"]["clangd"]["resource_dir"]
            .as_str()
            .unwrap();
        let data_directories = if selected == "cppcheck" {
            vec![
                ("analysis/cppcheck/cfg", ".cfg"),
                ("analysis/cppcheck/platforms", ".xml"),
            ]
        } else {
            vec![(resource, "")]
        };
        for (dir, suffix) in data_directories {
            let prefix = format!("{dir}/");
            let leaves: Vec<_> = namespace_expected
                .iter()
                .filter(|name| {
                    name.strip_prefix(&prefix).is_some_and(|leaf| {
                        (selected == "clangd" || !leaf.contains('/')) && leaf.ends_with(suffix)
                    })
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
        let required_data = if selected == "cppcheck" {
            "analysis/cppcheck/cfg/std.cfg".into()
        } else {
            format!("{resource}/include/stddef.h")
        };
        if !expected_leaves.contains(&required_data)
            || namespace_expected != expected_leaves
            || namespace(&root, budget, selected)? != namespace_expected
        {
            return Err(invalid(
                "Missing required data or unapproved analyzer namespace payload",
            ));
        }
        let mut directory_names = BTreeSet::new();
        for name in &namespace_expected {
            let mut parent = name.rsplit_once('/').map(|(parent, _)| parent);
            while let Some(directory) = parent {
                if !directory.starts_with(&format!("analysis/{selected}")) {
                    break;
                }
                directory_names.insert(directory.to_owned());
                parent = directory.rsplit_once('/').map(|(parent, _)| parent);
            }
        }
        directories.clear();
        for directory in directory_names {
            budget.remaining()?;
            let path = runtime_path(&root, &directory)?;
            directories.push((path.clone(), identity(&path)?));
        }
        let links = sbom["dependencies"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|d| d["ref"] == format!("byo-analysis:{selected}"))
            })
            .and_then(|d| d["dependsOn"].as_array())
            .ok_or_else(|| invalid("Analyzer SBOM dependencies missing"))?;
        for name in &namespace_expected {
            let kind = if name == &selected_executable {
                "analysis-executable"
            } else if selected_licenses.contains(name) {
                "license"
            } else if selected_dependencies.contains(name) {
                "analysis-dependency"
            } else {
                "analysis-data"
            };
            let bytes = payload(name, kind, kind == "analysis-executable")?;
            let digest = &inventory[name].sha256;
            let file_components: Vec<_> =
                components.iter().filter(|c| c["name"] == *name).collect();
            if file_components.len() != 1 {
                return Err(invalid(format!(
                    "Analyzer file SBOM identity missing/duplicated: {name}"
                )));
            }
            let component = file_components[0];
            let owner = format!("byo-analysis:{selected}");
            let properties = component["properties"].as_array();
            if component["type"] != "file"
                || component["bom-ref"] != format!("byo-analysis-file:{name}")
                || !links.contains(&component["bom-ref"])
                || !component["hashes"].as_array().is_some_and(|h| {
                    h.iter()
                        .any(|h| h["alg"] == "SHA-256" && h["content"] == *digest)
                })
                || properties.is_some_and(|p| {
                    p.iter()
                        .any(|p| p["name"] == "byo:analysis-owner" && p["value"] != owner)
                })
                || properties.is_some_and(|p| {
                    p.iter()
                        .any(|p| p["name"] == "byo:analysis-kind" && p["value"] != kind)
                })
                || sbom["dependencies"]
                    .as_array()
                    .is_some_and(|relationships| {
                        relationships.iter().any(|relationship| {
                            relationship["ref"] != owner
                                && relationship["dependsOn"]
                                    .as_array()
                                    .is_some_and(|references| {
                                        references.contains(&component["bom-ref"])
                                    })
                        })
                    })
            {
                return Err(invalid(format!(
                    "Analyzer payload SBOM relationship/hash missing: {name}"
                )));
            }
            if ["analysis-executable", "analysis-dependency"].contains(&kind) {
                target.validate(&bytes, kind == "analysis-dependency")?;
                if kind == "analysis-executable" {
                    executable_access(&runtime_path(&root, name)?)?;
                }
            }
        }
        let data_paths = if selected == "cppcheck" {
            json!({"cfg_dir":root.join("analysis/cppcheck/cfg"), "platforms_dir":root.join("analysis/cppcheck/platforms")})
        } else {
            json!({"resource_dir":root.join(resource)})
        };
        let fields = json!({"executable":root.join(&selected_executable),"executable_origin":"managed_runtime","executable_sha256":inventory[&selected_executable].sha256,"runtime_root":root,"runtime_manifest_sha256":crate::manifest::sha256_bytes(&manifest_bytes),"analysis_mapping_sha256":crate::manifest::sha256_bytes(&mapping_bytes),"data_paths":data_paths});
        Ok(Program {
            executable: root.join(&selected_executable),
            version: selected_version,
            fields,
            mapping,
            snapshots,
            directories,
            root,
            namespace: namespace_expected,
            selected,
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        root: PathBuf,
        release: ReleaseManifest,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn fixture() -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "byo-runtime-portable-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let root = canonical(&root).unwrap();
        let target = Target::host().unwrap();
        let platform = if cfg!(target_os = "macos") {
            "macos"
        } else {
            std::env::consts::OS
        };
        let mut mapping = json!({"schema_version":1,"platform":platform,"architecture":std::env::consts::ARCH,"programs":{}});
        for name in ["cppcheck", "clangd"] {
            let executable = target.executable(name);
            fs::create_dir_all(root.join(&executable).parent().unwrap()).unwrap();
            fs::copy(std::env::current_exe().unwrap(), root.join(&executable)).unwrap();
            let mut licenses: Vec<String> = if name == "cppcheck" {
                [
                    "COPYING",
                    "simplecpp-LICENSE",
                    "tinyxml2-LICENSE",
                    "picojson-LICENSE",
                ]
                .iter()
                .map(|v| format!("analysis/cppcheck/licenses/{v}"))
                .collect()
            } else {
                vec!["analysis/clangd/LICENSE.TXT".into()]
            };
            if name == "cppcheck" && target == Target::Linux {
                licenses.extend([
                    "analysis/cppcheck/licenses/GCC-COPYING3".into(),
                    "analysis/cppcheck/licenses/GCC-COPYING.RUNTIME".into(),
                ]);
            }
            for path in &licenses {
                fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                fs::write(root.join(path), b"fixture notice").unwrap();
            }
            let mut program = json!({"version":if name=="cppcheck" {"2.22.0"} else {"23.1.0"},"executable":executable,"licenses":licenses,"dependencies":[],"sbom_ref":format!("byo-analysis:{name}")});
            if name == "cppcheck" {
                program["cfg_dir"] = json!("analysis/cppcheck/cfg");
                program["platforms_dir"] = json!("analysis/cppcheck/platforms");
                for path in [
                    "analysis/cppcheck/cfg/std.cfg",
                    "analysis/cppcheck/platforms/target.xml",
                ] {
                    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                    fs::write(root.join(path), b"fixture data").unwrap();
                }
            } else {
                program["resource_dir"] = json!("analysis/clangd/lib/clang/23");
                fs::create_dir_all(root.join("analysis/clangd/lib/clang/23/include")).unwrap();
                fs::write(
                    root.join("analysis/clangd/lib/clang/23/include/stddef.h"),
                    b"fixture header",
                )
                .unwrap();
            }
            mapping["programs"][name] = program;
        }
        write_json(&root.join("analysis/runtime.json"), &mapping).unwrap();
        let mut components = Vec::new();
        let mut relationships = Vec::new();
        for name in ["cppcheck", "clangd"] {
            let owner = format!("byo-analysis:{name}");
            components.push(json!({"type":"application","bom-ref":owner,"name":name,"version":mapping["programs"][name]["version"],"licenses":[{"expression":"fixture"}],"properties":[{"name":"byo:analysis:upstream","value":"fixture"},{"name":"byo:analysis:recipe","value":"fixture"}]}));
            let mut references = Vec::new();
            for entry in walkdir::WalkDir::new(root.join(format!("analysis/{name}"))) {
                let entry = entry.unwrap();
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry
                    .path()
                    .strip_prefix(&root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/");
                let reference = format!("byo-analysis-file:{path}");
                components.push(json!({"type":"file","bom-ref":reference,"name":path,"hashes":[{"alg":"SHA-256","content":crate::manifest::sha256_file(entry.path()).unwrap()}]}));
                references.push(reference);
            }
            relationships.push(json!({"ref":owner,"dependsOn":references}));
        }
        write_json(
            &root.join("sbom.cdx.json"),
            &json!({"components":components,"dependencies":relationships}),
        )
        .unwrap();
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(&root) {
            let entry = entry.unwrap();
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .strip_prefix(&root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            let executable =
                [target.executable("cppcheck"), target.executable("clangd")].contains(&path);
            let kind = if executable {
                "analysis-executable"
            } else if path.contains("/licenses/") || path.ends_with("LICENSE.TXT") {
                "license"
            } else if ["analysis/runtime.json", "sbom.cdx.json"].contains(&path.as_str()) {
                "metadata"
            } else {
                "analysis-data"
            };
            files.push(ReleaseFile {
                path,
                sha256: crate::manifest::sha256_file(entry.path()).unwrap(),
                size: entry.metadata().unwrap().len(),
                kind: kind.into(),
                executable,
            });
        }
        let revision = json!({"repository":"fixture","commit":"fixture"});
        let release: ReleaseManifest = serde_json::from_value(json!({"schema":1,"product":"byo","version":"0.1.8","channel":"development","platform":platform,"architecture":std::env::consts::ARCH,"launcher_protocol":1,"sidecar_protocol":1,"worker_protocol":1,"workflow_protocol":1,"capsule_schema":1,"project_state_schema":1,"development_unsigned":true,"source":{"installer":revision,"agent_workspace":revision,"firmware_mcp":revision},"toolchain":{"rustc":"fixture","cargo":"fixture","python":"unused","nuitka":"unused"},"files":files})).unwrap();
        write_json(&root.join("release-manifest.json"), &release).unwrap();
        Fixture { root, release }
    }

    #[test]
    fn selected_payload_failure_does_not_invalidate_the_other_analyzer() {
        let fixture = fixture();
        let budget = Budget::new();
        resolve_selected(&fixture.root, &fixture.release, &budget, "clangd").unwrap();
        fs::write(
            fixture
                .root
                .join("analysis/clangd/lib/clang/23/include/stddef.h"),
            b"changed resource",
        )
        .unwrap();
        resolve(&fixture.root, &fixture.release, &budget).unwrap();
        assert!(resolve_selected(&fixture.root, &fixture.release, &budget, "clangd").is_err());
    }

    #[test]
    fn receipt_rejects_payload_or_namespace_change() {
        let fixture = fixture();
        let budget = Budget::new();
        let program = resolve(&fixture.root, &fixture.release, &budget).unwrap();
        fs::write(
            fixture.root.join("analysis/cppcheck/cfg/extra.cfg"),
            b"extra",
        )
        .unwrap();
        assert_eq!(
            program.recheck(&budget).unwrap_err().code,
            "analysis/configuration-changed"
        );
        assert!(resolve(&fixture.root, &fixture.release, &budget).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn execute_mode_is_required_and_participates_in_receipt_identity() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture();
        let budget = Budget::new();
        let program = resolve(&fixture.root, &fixture.release, &budget).unwrap();
        fs::set_permissions(&program.executable, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            program.recheck(&budget).unwrap_err().code,
            "analysis/configuration-changed"
        );
        assert!(resolve(&fixture.root, &fixture.release, &budget).is_err());
    }
}
