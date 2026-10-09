//! Shared schema-1 configuration, stable inputs and selected-build scope.
use super::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Identity {
    volume: u32,
    index: u64,
    size: u64,
    modified: u64,
}
pub(super) fn identity(path: &Path) -> std::io::Result<Identity> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // File holds this exact object open while Windows supplies its identity.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Identity {
        volume: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
    })
}
pub(super) fn same_file(first: &Path, second: &Path) -> std::io::Result<bool> {
    if first == second {
        return Ok(true);
    }
    let a = identity(first)?;
    let b = identity(second)?;
    Ok(a.volume == b.volume && a.index == b.index)
}
#[derive(Debug, Clone)]
pub(super) struct Snapshot {
    pub path: PathBuf,
    pub identity: Identity,
    pub hash: String,
}
impl Snapshot {
    pub fn capture(path: &Path, budget: &Budget) -> Result<(Self, Vec<u8>)> {
        let before = identity(path)?;
        let bytes = read(path, budget)?;
        if before != identity(path)? {
            return Err(Problem::execution(
                "configuration-changed",
                format!("Input changed while reading {}", path.display()),
            ));
        }
        Ok((
            Self {
                path: path.to_path_buf(),
                identity: before,
                hash: crate::manifest::sha256_bytes(&bytes),
            },
            bytes,
        ))
    }
    pub fn recheck(&self, budget: &Budget) -> Result<()> {
        if identity(&self.path)? != self.identity
            || crate::manifest::sha256_bytes(&read(&self.path, budget)?) != self.hash
        {
            return Err(Problem::execution(
                "configuration-changed",
                format!("Analysis input changed: {}", self.path.display()),
            ));
        }
        Ok(())
    }
}

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("strict JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("Non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<Strict>()? {
                    values.push(value.0);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("Duplicate JSON field {key}")));
                    }
                    values.insert(key, map.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        decoder.deserialize_any(StrictVisitor)
    }
}
pub(super) fn strict_json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<Strict>(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
        .map(|value| value.0)
        .map_err(|error| {
            Problem::blocked(
                "config-invalid",
                format!("Cannot parse JSON: {error}"),
                "Use schema 1 JSON without duplicate keys or non-finite numbers.",
            )
        })
}
pub(super) fn object<'a>(
    value: &'a Value,
    label: &str,
    allowed: &[&str],
    required: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let fields = value.as_object().ok_or_else(|| {
        Problem::blocked(
            "config-invalid",
            format!("{label} must be an object."),
            "Use documented schema 1 fields.",
        )
    })?;
    for name in fields.keys() {
        if !allowed.contains(&name.as_str()) {
            return Err(Problem::blocked(
                "config-invalid",
                format!("{label}.{name} is unknown."),
                "Remove the unknown field.",
            ));
        }
    }
    for name in required {
        if !fields.contains_key(*name) {
            return Err(Problem::blocked(
                "config-invalid",
                format!("{label}.{name} is required."),
                "Supply the required field.",
            ));
        }
    }
    Ok(fields)
}
pub(super) fn path_value(root: &Path, value: &Value, label: &str, code: &str) -> Result<PathBuf> {
    let raw = value
        .as_str()
        .filter(|v| {
            !v.trim().is_empty()
                && !v.contains('\0')
                && !v.contains("://")
                && !v.starts_with("//")
                && !v.starts_with(r"\\")
        })
        .ok_or_else(|| {
            Problem::blocked(
                code,
                format!("{label} must be a nonempty local path."),
                "Supply an absolute or project-relative local filesystem path.",
            )
        })?;
    let path = Path::new(raw);
    if path.has_root() && !path.is_absolute()
        || raw.as_bytes().get(1) == Some(&b':') && !path.is_absolute()
    {
        return Err(Problem::blocked(
            code,
            format!("{label} must not be drive-relative."),
            "Use an absolute or project-relative path.",
        ));
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    canonical(&candidate).map_err(|error| {
        Problem::blocked(
            code,
            format!("Cannot resolve {label} at {}: {error}", candidate.display()),
            format!("Supply an existing readable local path for {label}."),
        )
    })
}

#[derive(Debug, Clone)]
pub(super) struct Entry {
    pub source: PathBuf,
    pub directory: PathBuf,
    pub raw: Value,
}
#[derive(Debug)]
pub(super) struct Config {
    pub root: PathBuf,
    pub database: Option<PathBuf>,
    pub database_hash: Option<String>,
    pub platform: Option<PathBuf>,
    pub suppressions: Option<PathBuf>,
    pub style: bool,
    pub entries: Vec<Entry>,
    pub snapshots: Vec<Snapshot>,
    pub present: bool,
    pub warnings: Vec<String>,
}
impl Config {
    pub fn summary(&self, budget: &Budget) -> Value {
        json!({"compilation_database":self.database,"compilation_database_sha256":self.database_hash,"platform_file":self.platform,"timeout_seconds":budget.seconds,"warnings":self.warnings})
    }
    fn resource(
        &mut self,
        path: &Path,
        label: &str,
        code: &str,
        budget: &Budget,
    ) -> Result<Vec<u8>> {
        let (snapshot, bytes) = Snapshot::capture(path, budget).map_err(|error| {
            if error.code == "analysis/timeout" || error.code == "analysis/configuration-changed" {
                error
            } else {
                Problem::blocked(
                    code,
                    format!(
                        "Cannot read {label} at {}: {}",
                        path.display(),
                        error.message
                    ),
                    format!("Supply a readable file for {label}."),
                )
            }
        })?;
        self.snapshots.push(snapshot);
        Ok(bytes)
    }
}
fn validate_platform(bytes: &[u8]) -> Result<()> {
    let invalid = |message| {
        Problem::blocked("config-invalid",message,"Define every target ABI sizeof, char_bit and default-sign explicitly in cppcheck.platform_file.")
    };
    let doc = xml::parse(bytes).map_err(|e| invalid(format!("cppcheck.platform_file: {e}")))?;
    if doc.name != "platform" {
        return Err(invalid(
            "cppcheck.platform_file must contain a platform element.".into(),
        ));
    }
    for name in ["char_bit", "default-sign", "sizeof"] {
        if doc.named(name).len() != 1 {
            return Err(invalid(format!(
                "cppcheck.platform_file.{name} must occur exactly once."
            )));
        }
    }
    if !["signed", "unsigned"].contains(&doc.named("default-sign")[0].text.trim()) {
        return Err(invalid(
            "cppcheck.platform_file.default-sign must be signed or unsigned.".into(),
        ));
    }
    let sizes = doc.named("sizeof")[0];
    for name in [
        "char_bit",
        "bool",
        "short",
        "int",
        "long",
        "long-long",
        "float",
        "double",
        "long-double",
        "pointer",
        "size_t",
        "wchar_t",
    ] {
        let nodes = if name == "char_bit" {
            doc.named(name)
        } else {
            sizes.named(name)
        };
        if nodes.len() != 1
            || nodes[0].text.trim().is_empty()
            || !nodes[0].text.trim().bytes().all(|c| c.is_ascii_digit())
            || nodes[0]
                .text
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .is_none()
        {
            return Err(invalid(format!(
                "cppcheck.platform_file.{name} must occur once with a positive unsigned integer."
            )));
        }
    }
    Ok(())
}
pub(super) fn load_config(root: &Path, budget: &mut Budget) -> Result<Config> {
    let mut config = Config {
        root: canonical(root)?,
        database: None,
        database_hash: None,
        platform: None,
        suppressions: None,
        style: false,
        entries: Vec::new(),
        snapshots: Vec::new(),
        present: false,
        warnings: Vec::new(),
    };
    let loaded = (|| -> Result<()> {
        let config_path = config.root.join("byo-analysis.json");
        config.present = config_path.try_exists()?;
        let settings = if config.present {
            strict_json(&config.resource(
                &config_path,
                "byo-analysis.json",
                "config-invalid",
                budget,
            )?)?
        } else {
            json!({})
        };
        object(
            &settings,
            "byo-analysis.json",
            &[
                "schema_version",
                "compilation_database",
                "cppcheck",
                "clangd",
            ],
            if config.present {
                &["schema_version"]
            } else {
                &[]
            },
        )?;
        if config.present && settings["schema_version"].as_u64() != Some(1) {
            return Err(Problem::blocked(
                "config-invalid",
                "schema_version must be integer 1.",
                "Set schema_version to integer 1.",
            ));
        }
        let empty = json!({});
        let cpp = settings.get("cppcheck").unwrap_or(&empty);
        object(
            cpp,
            "cppcheck",
            &[
                "platform_file",
                "suppressions_file",
                "enable_style",
                "timeout_seconds",
            ],
            &[],
        )?;
        let clang = settings.get("clangd").unwrap_or(&empty);
        object(clang, "clangd", &["query_driver_paths"], &[])?;
        config.style = match cpp.get("enable_style") {
            None => false,
            Some(v) => v.as_bool().ok_or_else(|| {
                Problem::blocked(
                    "config-invalid",
                    "cppcheck.enable_style must be boolean.",
                    "Use true or false.",
                )
            })?,
        };
        let timeout = cpp
            .get("timeout_seconds")
            .map(|v| v.as_f64().unwrap_or(f64::NAN))
            .unwrap_or(120.0);
        budget.configure(timeout)?;
        for field in ["platform_file", "suppressions_file"] {
            if let Some(value) = cpp.get(field) {
                let path = path_value(
                    &config.root,
                    value,
                    &format!("cppcheck.{field}"),
                    "config-invalid",
                )?;
                let bytes = config.resource(
                    &path,
                    &format!("cppcheck.{field}"),
                    "config-invalid",
                    budget,
                )?;
                if field == "platform_file" {
                    config.platform = Some(path);
                    validate_platform(&bytes)?;
                } else {
                    config.suppressions = Some(path);
                }
            }
        }
        if let Some(drivers) = clang.get("query_driver_paths") {
            let drivers = drivers.as_array().ok_or_else(|| {
                Problem::blocked(
                    "config-invalid",
                    "clangd.query_driver_paths must be an array.",
                    "Use an array of exact compiler paths.",
                )
            })?;
            for (i, value) in drivers.iter().enumerate() {
                let raw = value.as_str().ok_or_else(|| {
                    Problem::blocked(
                        "config-invalid",
                        format!("clangd.query_driver_paths[{i}] must be a local path string."),
                        "Supply exact compiler paths.",
                    )
                })?;
                // Missing clangd-only resources warn; malformed path syntax still blocks.
                if raw.trim().is_empty()
                    || raw.contains('\0')
                    || raw.contains("://")
                    || raw.starts_with("//")
                    || raw.starts_with(r"\\")
                {
                    return Err(Problem::blocked(
                        "config-invalid",
                        format!("clangd.query_driver_paths[{i}] must be a nonempty local path."),
                        "Supply local paths.",
                    ));
                }
                if raw.as_bytes().get(1) == Some(&b':') && !Path::new(raw).is_absolute() {
                    return Err(Problem::blocked(
                        "config-invalid",
                        format!("clangd.query_driver_paths[{i}] must not be drive-relative."),
                        "Use an absolute or project-relative path.",
                    ));
                }
                if raw.contains(['*', '?', '[', ']', ',', '{', '}'])
                    || path_value(
                        &config.root,
                        value,
                        "clangd.query_driver_paths",
                        "config-invalid",
                    )
                    .ok()
                    .is_none_or(|p| {
                        !p.is_file()
                            || p.extension().is_some_and(|e| {
                                e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd")
                            })
                    })
                {
                    config.warnings.push(format!("clangd.query_driver_paths[{i}] is not an exact usable compiler executable; correct before semantic queries. It is not used by Cppcheck."));
                }
            }
        }
        let chosen = if let Some(value) = settings.get("compilation_database") {
            path_value(
                &config.root,
                value,
                "compilation_database",
                "database-invalid",
            )?
        } else {
            let mut candidates: Vec<PathBuf> = Vec::new();
            for path in [
                config.root.join("compile_commands.json"),
                config.root.join("build/compile_commands.json"),
            ] {
                if path.try_exists()?
                    && !candidates
                        .iter()
                        .any(|p| same_file(&path, p).unwrap_or(false))
                {
                    candidates.push(canonical(&path)?);
                }
            }
            match candidates.len(){0=>return Err(Problem::blocked("database-missing","No compile_commands.json in project root or build/.","Export the native build database and set compilation_database in byo-analysis.json.")),1=>candidates.remove(0),_=>return Err(Problem::blocked("database-ambiguous","Multiple distinct compilation databases exist.","Set compilation_database explicitly in byo-analysis.json."))}
        };
        config.database = Some(chosen.clone());
        if chosen.file_name() != Some(std::ffi::OsStr::new("compile_commands.json")) {
            return Err(Problem::blocked(
                "database-invalid",
                "compilation_database must be named compile_commands.json.",
                "Re-export with that filename.",
            ));
        }
        let bytes = config.resource(&chosen, "compilation_database", "database-invalid", budget)?;
        config.database_hash = Some(crate::manifest::sha256_bytes(&bytes));
        let database = strict_json(&bytes).map_err(|e| {
            Problem::blocked(
                "database-invalid",
                format!("Cannot parse compilation_database: {}", e.message),
                "Re-export exact native build commands as JSON.",
            )
        })?;
        let records = database
            .as_array()
            .filter(|r| !r.is_empty())
            .ok_or_else(|| {
                Problem::blocked(
                    "database-invalid",
                    "compilation_database must be a nonempty command array.",
                    "Export the selected native build.",
                )
            })?;
        let mut sources: BTreeMap<(u32, u64), Entry> = BTreeMap::new();
        for (i, record) in records.iter().enumerate() {
            budget.remaining()?;
            let label = format!("compilation_database[{i}]");
            if !record.is_object() {
                return Err(Problem::blocked(
                    "database-invalid",
                    format!("{label} must be an object."),
                    "Re-export the database.",
                ));
            }
            let directory = path_value(
                &config.root,
                &record["directory"],
                &format!("{label}.directory"),
                "database-invalid",
            )?;
            if !directory.is_dir() {
                return Err(Problem::blocked(
                    "database-invalid",
                    format!("{label}.directory must exist as a directory."),
                    "Build generated inputs or re-export.",
                ));
            }
            let source = path_value(
                &directory,
                &record["file"],
                &format!("{label}.file"),
                "database-invalid",
            )?;
            if !source.is_file() {
                return Err(Problem::blocked(
                    "database-invalid",
                    format!("{label}.file must be a source file."),
                    "Build generated inputs or re-export.",
                ));
            }
            if let Some(args) = record.get("arguments") {
                if !args.as_array().is_some_and(|a| {
                    !a.is_empty()
                        && a.iter()
                            .all(|v| v.as_str().is_some_and(|s| !s.contains('\0')))
                        && a[0].as_str().is_some_and(|s| !s.trim().is_empty())
                }) {
                    return Err(Problem::blocked(
                        "database-invalid",
                        format!("{label}.arguments must be a nonempty string array."),
                        "Re-export exact compiler argv.",
                    ));
                }
            }
            if let Some(command) = record.get("command") {
                if !command
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty() && !s.contains('\0'))
                {
                    return Err(Problem::blocked(
                        "database-invalid",
                        format!("{label}.command must be a nonempty string."),
                        "Re-export the command.",
                    ));
                }
            }
            if record
                .get("arguments")
                .or_else(|| record.get("command"))
                .is_none()
            {
                return Err(Problem::blocked(
                    "database-invalid",
                    format!("{label} needs arguments or command."),
                    "Export compiler commands for one configuration.",
                ));
            }
            let entry = Entry {
                source: source.clone(),
                directory,
                raw: record.clone(),
            };
            let id = identity(&source)?;
            if let Some(previous) = sources.get(&(id.volume, id.index)) {
                let repr = |e: &Entry| e.raw.get("arguments").unwrap_or(&e.raw["command"]).clone();
                if previous.directory != entry.directory || repr(previous) != repr(&entry) {
                    return Err(Problem::blocked(
                        "database-conflict",
                        format!("Conflicting commands for {}", source.display()),
                        "Export/select one build configuration.",
                    ));
                }
            } else {
                sources.insert((id.volume, id.index), entry.clone());
                config.entries.push(entry);
            }
        }
        budget.remaining()?;
        Ok(())
    })();
    if let Err(mut error) = loaded {
        merge(&mut error.details, config.summary(budget));
        return Err(error);
    }
    Ok(config)
}
#[derive(Debug, Serialize)]
pub(super) struct Scope {
    pub requested_path: String,
    pub kind: String,
    pub translation_units: Vec<PathBuf>,
    pub selected_count: usize,
}
const SOURCES: &[&str] = &["c", "cc", "cpp", "cxx", "c++"];
pub(super) fn select_scope(
    config: &Config,
    target: &str,
    budget: &Budget,
) -> Result<(Scope, Vec<Entry>)> {
    budget.remaining()?;
    let path = path_value(&config.root, &json!(target), "verify path", "scope-empty")?;
    let suffix = path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    let kind = if target == "." {
        "all"
    } else if path.is_dir() {
        "directory"
    } else if ["h", "hh", "hpp", "hxx", "h++", "inc", "inl", "tpp"].contains(&suffix.as_str()) {
        "header_all"
    } else {
        "source"
    };
    let entries: Vec<_> = config
        .entries
        .iter()
        .filter(|e| match kind {
            "directory" => e.source.starts_with(&path),
            "source" => {
                SOURCES.contains(&suffix.as_str()) && same_file(&e.source, &path).unwrap_or(false)
            }
            _ => true,
        })
        .cloned()
        .collect();
    let scope = Scope {
        requested_path: target.into(),
        kind: kind.into(),
        translation_units: entries.iter().map(|e| e.source.clone()).collect(),
        selected_count: entries.len(),
    };
    let invalid = if entries.is_empty() {
        Some(("scope-empty", "Zero selected translation units."))
    } else if entries.iter().any(|e| {
        !SOURCES.contains(
            &e.source
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase()
                .as_str(),
        )
    }) {
        Some((
            "coverage-incomplete",
            "Selected units are outside Cppcheck C/C++ coverage.",
        ))
    } else {
        None
    };
    if let Some((code, message)) = invalid {
        let mut error=Problem::blocked(code,message,"Select a C/C++ path covered by the selected database; separately verify assembly/vendor inputs.");
        error.details = json!({"scope":scope});
        return Err(error);
    }
    Ok((scope, entries))
}
