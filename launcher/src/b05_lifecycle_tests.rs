//! B05 regressions. Compiled/executed only in Actions; fixtures never use hardware.
use super::*;
#[cfg(feature = "development")]
use std::io::Write;

fn fixture() -> (PathBuf, ProductPaths, PathBuf) {
    let root = std::env::temp_dir().join(format!("byo-b05-{:032x}", rand::random::<u128>()));
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();
    let paths = ProductPaths::from_install_dir(&root.join("product")).unwrap();
    (root, paths, project)
}

#[cfg(feature = "development")]
fn workspace(paths: &ProductPaths, version: &str, full: bool, approval: &str) -> PathBuf {
    let runtime = paths.versions().join(version);
    std::fs::create_dir_all(runtime.join("workflow")).unwrap();
    let catalog = serde_json::json!({
        "schema": 2, "workflow_protocol": 1, "skills": {}, "agents": {},
        "modes": [{"name": "firmware", "family": "firmware", "extends": [],
            "full_access": full, "skills": [], "instruction_resources": [],
            "verify": {"backend": "firmware", "required_tools": []},
            "codex": {"permission_profile": "default", "sandbox_mode": "workspace-write",
                "approval_policy": approval, "web_search": "disabled"},
            "workflow": {"one_way_doors": [], "adversarial_triggers": []},
            "structure": {"version": 1, "default_visibility": "private", "required_dirs": [],
                "required_files": [], "forbidden_paths": []}}]
    });
    let resources = [
        (
            "compiled/workflow.json",
            serde_json::to_vec(&catalog).unwrap(),
        ),
        ("templates/PLAN.template.md", b"plan template\n".to_vec()),
        (
            "templates/HANDOFF.template.md",
            b"handoff template\n".to_vec(),
        ),
    ];
    let mut body = Vec::new();
    let mut index = Vec::new();
    for (id, bytes) in resources {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&bytes).unwrap();
        let compressed = encoder.finish().unwrap();
        index.push(serde_json::json!({"id": id, "class": "fixture", "sha256": sha256_bytes(&bytes),
            "offset": body.len(), "compressed_size": compressed.len(), "original_size": bytes.len()}));
        body.extend(compressed);
    }
    let header = serde_json::to_vec(&serde_json::json!({"schema": 1, "product": "byo",
        "workspace_version": version, "workflow_protocol": 1, "compression": "zlib", "resources": index})).unwrap();
    let mut pack = b"BYOWPK1\n".to_vec();
    pack.extend_from_slice(&(header.len() as u64).to_be_bytes());
    pack.extend(header);
    pack.extend(body);
    std::fs::write(runtime.join("workflow/workspace.pack"), &pack).unwrap();
    let source = serde_json::json!({"repository": "fixture", "commit": "0".repeat(40)});
    write_json(&runtime.join("release-manifest.json"), &serde_json::json!({
        "schema": 1, "product": "byo", "version": version, "channel": "development",
        "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "launcher_protocol": 1, "sidecar_protocol": 1, "worker_protocol": 1,
        "workflow_protocol": 1, "capsule_schema": 1, "project_state_schema": 1,
        "development_unsigned": true,
        "source": {"installer": source, "agent_workspace": source, "firmware_mcp": source},
        "toolchain": {"rustc": "fixture", "cargo": "fixture", "python": "fixture", "nuitka": "fixture"},
        "files": [{"path": "workflow/workspace.pack", "kind": "workflow-pack", "executable": false,
            "sha256": sha256_bytes(&pack), "size": pack.len()}]
    })).unwrap();
    write_json(
        &paths.current(),
        &crate::manifest::CurrentRuntime {
            schema: 1,
            version: version.to_string(),
            relative_runtime: format!("versions/{version}"),
            manifest_sha256: sha256_file(&runtime.join("release-manifest.json")).unwrap(),
        },
    )
    .unwrap();
    runtime
}

#[cfg(feature = "development")]
fn refresh(project: &Path, paths: &ProductPaths) -> Result<()> {
    let lock = crate::install::InstallLock::acquire(paths)?;
    refresh_project_locked(project, paths, &lock)
}

#[test]
fn semantic_comparisons_preserve_values_and_refuse_ambiguous_keys() {
    assert!(same_owned_text("skill.md", "instructions\r\n\r\n", "instructions\n").unwrap());
    assert!(!same_owned_text("skill.md", "other instructions\n", "instructions\n").unwrap());
    assert!(same_owned_text("mode.json", "{\"b\": 2,\"a\":1}", "{\"a\":1,\"b\":2}\n").unwrap());
    assert!(same_owned_text("mode.json", "{\"a\":0,\"a\":1}", "{\"a\":1}").is_err());
    assert!(parse_project_json::<serde_json::Value>(
        br#"{"permissions":{"allow":false,"allow":true}}"#
    )
    .is_err());
    let a = "command = 'byo'\nargs = ['mcp', 'serve']\nenv = { FOO = 'bar', BAZ = 'qux' }\n"
        .parse::<DocumentMut>()
        .unwrap();
    let b = "# comment\nenv={BAZ=\"qux\",FOO=\"bar\"}\nargs=[\"mcp\",\"serve\"] # comment\ncommand=\"byo\"\n".parse::<DocumentMut>().unwrap();
    assert_eq!(
        toml_semantics(a.as_item()).unwrap(),
        toml_semantics(b.as_item()).unwrap()
    );
    assert!("command='byo'\ncommand='other'"
        .parse::<DocumentMut>()
        .is_err());
}

#[cfg(feature = "development")]
#[test]
fn formatting_survives_doctor_guard_and_init_but_meaningful_changes_refuse() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    for relative in [
        "AGENTS.md",
        "CLAUDE.md",
        ".agents/skills/byo-firmware/SKILL.md",
        ".claude/skills/byo-firmware/SKILL.md",
    ] {
        let target = project.join(relative);
        let text = std::fs::read_to_string(&target).unwrap();
        std::fs::write(target, text.replace('\n', "\r\n") + "\r\n").unwrap();
    }
    let codex = project.join(".codex/config.toml");
    let document = std::fs::read_to_string(&codex)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    let args = document["mcp_servers"]["byo"]["args"].to_string();
    std::fs::write(
        &codex,
        format!("customer=true\n[mcp_servers.byo]\n# formatting\nargs={args}\ncommand='byo'\n"),
    )
    .unwrap();
    for relative in [
        ".generated/byo/active-mode.json",
        INTEGRITY_PATH,
        ".codex/hooks.json",
        ".mcp.json",
        ".claude/settings.json",
    ] {
        let target = project.join(relative);
        let json: serde_json::Value = parse_project_json(&std::fs::read(&target).unwrap()).unwrap();
        std::fs::write(target, serde_json::to_vec(&json).unwrap()).unwrap();
    }
    doctor_project(&project, &paths).unwrap();
    assert_eq!(guard_mode(&project).unwrap(), "firmware");
    let original = std::fs::read(&codex).unwrap();
    std::fs::write(
        &codex,
        String::from_utf8(original.clone())
            .unwrap()
            .replace("command='byo'", "command='other'"),
    )
    .unwrap();
    assert!(doctor_project(&project, &paths).is_err());
    assert!(init_project(&project, "firmware", false, false, &paths).is_err());
    std::fs::write(&codex, original).unwrap();
    init_project(&project, "firmware", false, false, &paths).unwrap();
    assert!(std::fs::read_to_string(&codex)
        .unwrap()
        .contains("customer=true"));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn compatible_refresh_upgrade_rollback_and_missing_old_runtime_preserve_state() {
    let (root, paths, project) = fixture();
    let old = workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let id = project_id(&project).unwrap();
    std::fs::write(project.join(".agent-workspace/PLAN.md"), b"my plan\n").unwrap();
    std::fs::write(project.join(".agent-workspace/HANDOFF.md"), b"my handoff\n").unwrap();
    workspace(&paths, "0.1.9", false, "on-request");
    std::fs::remove_dir_all(old).unwrap();
    refresh(&project, &paths).unwrap();
    assert_eq!(
        read_capsule(&project).unwrap().unwrap().workspace_version,
        "0.1.9"
    );
    assert_eq!(project_id(&project).unwrap(), id);
    workspace(&paths, "0.1.8", false, "on-request");
    refresh(&project, &paths).unwrap();
    assert_eq!(
        read_capsule(&project).unwrap().unwrap().workspace_version,
        "0.1.8"
    );
    assert_eq!(
        std::fs::read(project.join(".agent-workspace/PLAN.md")).unwrap(),
        b"my plan\n"
    );
    assert_eq!(
        std::fs::read(project.join(".agent-workspace/HANDOFF.md")).unwrap(),
        b"my handoff\n"
    );
    doctor_project(&project, &paths).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn owned_toml_preserves_nested_settings_without_copying_secrets_to_baseline() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    std::fs::create_dir_all(project.join(".codex")).unwrap();
    let codex = project.join(".codex/config.toml");
    std::fs::write(&codex, "customer=true\n[mcp_servers.byo]\ncommand='byo'\nenv={TOKEN='private-test-token',FEATURE='on'}\n").unwrap();
    init_project(&project, "firmware", false, false, &paths).unwrap();
    assert!(!std::fs::read_to_string(project.join(INTEGRITY_PATH))
        .unwrap()
        .contains("private-test-token"));
    let doc = std::fs::read_to_string(&codex)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    let formatted = format!("customer=true\n[mcp_servers]\nbyo = {{ env = {{FEATURE='on',TOKEN='private-test-token'}}, args={}, command='byo' }}\n", doc["mcp_servers"]["byo"]["args"]);
    std::fs::write(&codex, &formatted).unwrap();
    doctor_project(&project, &paths).unwrap();
    init_project(&project, "firmware", false, false, &paths).unwrap();
    doctor_project(&project, &paths).unwrap();
    let valid = std::fs::read_to_string(&codex).unwrap();
    std::fs::write(&codex, valid.replace("private-test-token", "other-token")).unwrap();
    assert!(doctor_project(&project, &paths).is_err());
    assert!(init_project(&project, "firmware", false, false, &paths).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn leases_and_changed_permissions_refuse_without_changing_capsule() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let capsule = project.join(".agent-workspace/manifest.json");
    let before = std::fs::read(&capsule).unwrap();
    let lease =
        crate::lease::RuntimeLeaseGuard::acquire(&paths, "0.1.8", &project_id(&project).unwrap())
            .unwrap();
    refresh(&project, &paths).unwrap(); // Healthy no-op is allowed in a session.
    workspace(&paths, "0.1.9", false, "on-request");
    assert!(refresh(&project, &paths).is_err());
    assert_eq!(std::fs::read(&capsule).unwrap(), before);
    drop(lease);
    workspace(&paths, "0.2.0", true, "never");
    assert!(refresh(&project, &paths)
        .unwrap_err()
        .to_string()
        .contains("permissions"));
    assert_eq!(std::fs::read(&capsule).unwrap(), before);
    init_project(&project, "firmware", false, true, &paths).unwrap(); // Explicit grant.
    workspace(&paths, "0.2.1", true, "never");
    refresh(&project, &paths).unwrap();
    assert!(guard_mode(&project).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_refresh_recovers_only_owned_transaction_bytes_and_registry_aliases() {
    let (root, paths, project) = fixture();
    std::fs::write(project.join("AGENTS.md"), b"original user text\n").unwrap();
    let backup_root = project_backup_root(&paths, &project).unwrap();
    let backup = backup_root.join("20261020T000000Z-0123456789abcdef");
    crate::paths::ensure_private_directory(&backup).unwrap();
    let targets = vec!["AGENTS.md".to_string()];
    let existed = copy_backup(&project, &backup, &targets).unwrap();
    let pending = PendingRefresh {
        schema: 1,
        project: project.display().to_string(),
        backup: backup.file_name().unwrap().to_string_lossy().into_owned(),
        targets,
        existed,
        expected: BTreeMap::from([(
            "AGENTS.md".to_string(),
            Some(sha256_bytes(b"planned replacement\n")),
        )]),
        registry_before: None,
        legacy_workspace: false,
        registry_aliases: BTreeMap::from([(
            "original-id".to_string(),
            project.display().to_string(),
        )]),
    };
    write_json(&backup_root.join("pending.json"), &pending).unwrap();
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::from([("other-id", "another-project")]),
    )
    .unwrap();
    std::fs::write(
        project.join("AGENTS.md"),
        b"new user edit after interruption\n",
    )
    .unwrap();
    assert!(recover_project_refresh(&project, &paths).is_err());
    assert_eq!(
        std::fs::read(project.join("AGENTS.md")).unwrap(),
        b"new user edit after interruption\n"
    );
    std::fs::write(project.join("AGENTS.md"), b"planned replacement\n").unwrap();
    recover_project_refresh(&project, &paths).unwrap();
    assert_eq!(
        std::fs::read(project.join("AGENTS.md")).unwrap(),
        b"original user text\n"
    );
    assert_eq!(
        project_registry(&paths).unwrap().get("other-id").unwrap(),
        "another-project"
    );
    assert!(!backup_root.join("pending.json").exists());
    recover_project_refresh(&project, &paths).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn legacy_byte_records_accept_normal_formatting_before_refresh() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let mut projection = read_projection(&project).unwrap().unwrap();
    projection
        .managed_files
        .retain(|file| file.path != INTEGRITY_PATH);
    write_json(
        &project.join(".generated/byo/projection-manifest.json"),
        &projection,
    )
    .unwrap();
    std::fs::remove_file(project.join(INTEGRITY_PATH)).unwrap();
    let skill = project.join(".agents/skills/byo-firmware/SKILL.md");
    std::fs::write(
        &skill,
        std::fs::read_to_string(&skill)
            .unwrap()
            .replace('\n', "\r\n"),
    )
    .unwrap();
    let codex = project.join(".codex/config.toml");
    let doc = std::fs::read_to_string(&codex)
        .unwrap()
        .parse::<DocumentMut>()
        .unwrap();
    std::fs::write(
        &codex,
        format!(
            "[mcp_servers.byo]\nargs={} # moved\ncommand='byo'\n",
            doc["mcp_servers"]["byo"]["args"]
        ),
    )
    .unwrap();
    let active = project.join(".generated/byo/active-mode.json");
    let json: serde_json::Value = parse_project_json(&std::fs::read(&active).unwrap()).unwrap();
    std::fs::write(&active, serde_json::to_vec(&json).unwrap()).unwrap();
    workspace(&paths, "0.1.9", false, "on-request");
    refresh(&project, &paths).unwrap();
    doctor_project(&project, &paths).unwrap();
    assert!(project.join(INTEGRITY_PATH).is_file());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
fn native_runtime(root: &Path, version: &str, failure: &str) {
    // Only Actions executes these tests. Compile the existing tiny native
    // contract fixture, adding just the versioned refresh capability response.
    static EXECUTABLE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let executable = EXECUTABLE.get_or_init(|| {
        let build = std::env::temp_dir().join(format!("byo-b05-native-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&build).unwrap();
        let source = include_str!("../tests/fixtures/runtime-switch/fake_runtime.rs")
            .replace("    let executable = std::env::current_exe().unwrap();",
                "    if args.get(1).map(String::as_str) == Some(\"edit\") { std::fs::write(&args[2], std::fs::read(&args[3]).unwrap()).unwrap(); return; }\n    let executable = std::env::current_exe().unwrap();")
            .replace("args.get(1).map(String::as_str) == Some(\"doctor\")",
                "(args.get(1).map(String::as_str) == Some(\"doctor\") || args.get(2).map(String::as_str) == Some(\"activation-doctor\"))")
            .replace("let failure = fields.next().unwrap_or(\"\");",
                "let failure = fields.next().unwrap_or(\"\");\nif args.get(2).map(String::as_str) == Some(\"project-refresh-protocol\") { if failure == \"legacy\" { std::process::exit(2); } println!(\"1\"); return; }");
        let input = build.join("fake.rs");
        let output = build.join(if cfg!(windows) { "fake.exe" } else { "fake" });
        std::fs::write(&input, source).unwrap();
        let result = std::process::Command::new("rustc").arg(&input).arg("-o").arg(&output).output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let bytes = std::fs::read(output).unwrap();
        std::fs::remove_dir_all(build).unwrap();
        bytes
    });
    std::fs::create_dir_all(root.join("sidecar")).unwrap();
    std::fs::create_dir_all(root.join("workflow")).unwrap();
    let launcher = crate::install::launcher_path(root);
    let sidecar = crate::install::sidecar_path(root);
    for file in [&launcher, &sidecar] {
        let mut bytes = executable.clone();
        bytes.extend_from_slice(version.as_bytes());
        std::fs::write(file, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    std::fs::write(
        root.join("runtime-test-identity"),
        format!("{version}\n{failure}\n"),
    )
    .unwrap();
    let header = serde_json::to_vec(
        &serde_json::json!({"schema": 1, "product": "byo", "workspace_version": version,
        "workflow_protocol": 1, "compression": "zlib", "resources": []}),
    )
    .unwrap();
    let mut pack = b"BYOWPK1\n".to_vec();
    pack.extend_from_slice(&(header.len() as u64).to_be_bytes());
    pack.extend(header);
    std::fs::write(root.join("workflow/workspace.pack"), pack).unwrap();
    let files: Vec<_> = [
        (launcher, "launcher", true),
        (sidecar, "sidecar", true),
        (root.join("workflow/workspace.pack"), "workflow-pack", false),
        (root.join("runtime-test-identity"), "metadata", false),
    ]
    .into_iter()
    .map(|(path, kind, executable)| {
        serde_json::json!({
            "path": path.strip_prefix(root).unwrap().to_str().unwrap().replace('\\', "/"),
            "kind": kind, "executable": executable, "size": std::fs::metadata(&path).unwrap().len(),
            "sha256": sha256_file(&path).unwrap()
        })
    })
    .collect();
    let source = serde_json::json!({"repository": "fixture", "commit": "0".repeat(40)});
    write_json(&root.join("release-manifest.json"), &serde_json::json!({
        "schema": 1, "product": "byo", "version": version, "channel": "development",
        "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "launcher_protocol": 1, "sidecar_protocol": 1, "worker_protocol": 1, "workflow_protocol": 1,
        "capsule_schema": 1, "project_state_schema": 1, "development_unsigned": true,
        "source": {"installer": source, "agent_workspace": source, "firmware_mcp": source},
        "toolchain": {"rustc": "fixture", "cargo": "fixture", "python": "fixture", "nuitka": "fixture"},
        "files": files
    })).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn native_rollback_checks_capability_target_version_leases_and_activation_rollback() {
    let (root, paths, project) = fixture();
    let prior = root.join("prior");
    let latest = root.join("latest");
    native_runtime(&prior, "99.0.1", "");
    native_runtime(&latest, "99.0.2", "");
    crate::install::install_bundle(&prior, &paths).unwrap();
    crate::install::install_bundle(&latest, &paths).unwrap();
    // Real process fixture enforces the selected version at --launcher-version.
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::from([("project", project.display().to_string())]),
    )
    .unwrap();
    let lease = crate::lease::RuntimeLeaseGuard::acquire(&paths, "99.0.2", "project").unwrap();
    let before = [
        std::fs::read(paths.current()).unwrap(),
        std::fs::read(paths.public_launcher()).unwrap(),
    ];
    assert!(crate::update::rollback(&paths, Some("99.0.1")).is_err());
    drop(lease);
    let restored = crate::update::rollback(&paths, Some("99.0.1")).unwrap();
    assert_eq!(
        crate::manifest::load_current(&paths).unwrap().0.version,
        "99.0.1"
    );
    assert_eq!(restored.file_name().unwrap(), "99.0.1");
    let lock = crate::install::InstallLock::acquire(&paths).unwrap();
    crate::install::install_bundle_locked(&latest, &paths, &lock).unwrap();
    drop(lock);
    let bad = root.join("bad");
    native_runtime(&bad, "99.0.3", "doctor");
    assert!(crate::install::install_bundle(&bad, &paths).is_err());
    // Make the failing doctor target a rollback candidate, keeping the healthy
    // current launcher/pointer fixed through both kinds of activation failure.
    crate::install::install_bundle(&latest, &paths).unwrap();
    assert!(crate::update::rollback(&paths, Some("99.0.3")).is_err());
    assert_eq!(
        [
            std::fs::read(paths.current()).unwrap(),
            std::fs::read(paths.public_launcher()).unwrap()
        ],
        before
    );
    let activation = root.join("activation-failure");
    native_runtime(&activation, "99.0.4", "activation");
    assert!(crate::install::install_bundle(&activation, &paths).is_err());
    assert!(crate::update::rollback(&paths, Some("99.0.4")).is_err());
    assert_eq!(
        [
            std::fs::read(paths.current()).unwrap(),
            std::fs::read(paths.public_launcher()).unwrap()
        ],
        before
    );
    let legacy = root.join("legacy");
    native_runtime(&legacy, "98.0.0", "legacy");
    assert!(crate::install::install_bundle(&legacy, &paths).is_err());
    let error = crate::update::rollback(&paths, Some("98.0.0")).unwrap_err();
    assert!(error
        .to_string()
        .contains("predates automatic project refresh"));
    assert_eq!(
        [
            std::fs::read(paths.current()).unwrap(),
            std::fs::read(paths.public_launcher()).unwrap()
        ],
        before
    );
    // Initial/empty-product rollback remains supported for the old launcher.
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::<String, String>::new(),
    )
    .unwrap();
    crate::update::rollback(&paths, Some("98.0.0")).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn review_repair_refuses_incapable_target_with_registered_projects() {
    let (root, paths, project) = fixture();
    let prior = root.join("legacy");
    let current = root.join("current");
    native_runtime(&prior, "98.0.0", "legacy");
    native_runtime(&current, "99.0.2", "");
    // Empty registry permits the old launcher: positive setup control.
    crate::install::install_bundle(&prior, &paths).unwrap();
    crate::install::install_bundle(&current, &paths).unwrap();
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::from([("project", project.display().to_string())]),
    )
    .unwrap();
    let before = [
        std::fs::read(paths.current()).unwrap(),
        std::fs::read(paths.public_launcher()).unwrap(),
        std::fs::read(paths.install_locator()).unwrap(),
    ];
    let target = paths.versions().join("98.0.0");
    let outcome = crate::install::repair(&paths, Some(&target));
    assert!(
        outcome.is_err(),
        "repair activated an incapable legacy launcher"
    );
    assert_eq!(
        [
            std::fs::read(paths.current()).unwrap(),
            std::fs::read(paths.public_launcher()).unwrap(),
            std::fs::read(paths.install_locator()).unwrap(),
        ],
        before
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn review_direct_install_refuses_existing_live_session() {
    let (root, paths, project) = fixture();
    let current = root.join("current");
    let next = root.join("next");
    native_runtime(&current, "99.0.1", "");
    native_runtime(&next, "99.0.2", "");
    crate::install::install_bundle(&current, &paths).unwrap();
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::from([("project", project.display().to_string())]),
    )
    .unwrap();
    let before = std::fs::read(paths.current()).unwrap();
    let session = crate::lease::RuntimeLeaseGuard::acquire(&paths, "99.0.1", "project").unwrap();
    let outcome = crate::install::install_bundle(&next, &paths);
    assert!(
        outcome.is_err(),
        "install-runtime switched during a live lease"
    );
    assert_eq!(std::fs::read(paths.current()).unwrap(), before);
    drop(session);
    // Same capable candidate must be usable once the session is stopped.
    crate::install::install_bundle(&next, &paths).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn review_project_uninstall_refuses_live_lease_before_removing_files() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let capsule = project.join(".agent-workspace/manifest.json");
    let before = std::fs::read(&capsule).unwrap();
    let session =
        crate::lease::RuntimeLeaseGuard::acquire(&paths, "0.1.8", &project_id(&project).unwrap())
            .unwrap();
    let outcome = uninstall_project(&project, &paths, false);
    assert!(
        outcome.is_err(),
        "project uninstall removed a live integration"
    );
    assert_eq!(std::fs::read(&capsule).unwrap(), before);
    drop(session);
    uninstall_project(&project, &paths, false).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn review_legacy_uninstall_refuses_meaningful_owned_command_edit() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    // Strip just the optional B05 semantic baseline to model a deployed v1
    // capsule. Its exact byte hashes remain available and are not weakened.
    let projection_path = project.join(".generated/byo/projection-manifest.json");
    let mut projection = read_projection(&project).unwrap().unwrap();
    projection
        .managed_files
        .retain(|file| file.path != INTEGRITY_PATH);
    write_json(&projection_path, &projection).unwrap();
    std::fs::remove_file(project.join(INTEGRITY_PATH)).unwrap();
    let codex = project.join(".codex/config.toml");
    let original = std::fs::read_to_string(&codex).unwrap();
    let changed = original.replace("\"byo\"", "\"my-server\"");
    assert_ne!(changed, original);
    std::fs::write(&codex, &changed).unwrap();
    // The same owned edit already refuses doctor/init on this legacy capsule.
    assert!(doctor_project(&project, &paths).is_err());
    assert!(init_project(&project, "firmware", false, false, &paths).is_err());
    let outcome = uninstall_project(&project, &paths, false);
    assert!(
        outcome.is_err(),
        "legacy uninstall silently removed the edited table"
    );
    assert_eq!(std::fs::read_to_string(&codex).unwrap(), changed);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
fn activation_bytes(paths: &ProductPaths) -> [Vec<u8>; 3] {
    [
        paths.current(),
        paths.public_launcher(),
        paths.install_locator(),
    ]
    .map(|path| std::fs::read(path).unwrap())
}

#[cfg(feature = "development")]
#[test]
fn repair_and_direct_install_share_refusal_rollback_and_idempotent_controls() {
    let (root, paths, project) = fixture();
    let legacy = root.join("legacy");
    let healthy = root.join("healthy");
    let bad = root.join("bad");
    native_runtime(&legacy, "98.0.0", "legacy");
    native_runtime(&healthy, "99.0.1", "");
    native_runtime(&bad, "99.0.2", "doctor");
    crate::install::install_bundle(&legacy, &paths).unwrap();
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::from([("project", project.display().to_string())]),
    )
    .unwrap();
    let before = activation_bytes(&paths);
    // Intentional repair/reinstall of this exact incapable runtime stays usable.
    crate::install::repair(&paths, None).unwrap();
    crate::install::install_bundle(&legacy, &paths).unwrap();
    assert_eq!(activation_bytes(&paths), before);
    let session = crate::lease::RuntimeLeaseGuard::acquire(&paths, "98.0.0", "project").unwrap();
    assert!(crate::install::repair(&paths, None).is_err());
    assert_eq!(activation_bytes(&paths), before);
    drop(session);
    crate::install::install_bundle(&healthy, &paths).unwrap();
    let before = activation_bytes(&paths);
    assert!(crate::install::install_bundle(&legacy, &paths).is_err());
    assert_eq!(activation_bytes(&paths), before);
    // Post-activation doctor fails after pointer/public/locator publication.
    assert!(crate::install::install_bundle(&bad, &paths).is_err());
    assert_eq!(activation_bytes(&paths), before);
    assert!(crate::install::repair(&paths, Some(&paths.versions().join("99.0.2"))).is_err());
    assert_eq!(activation_bytes(&paths), before);
    assert!(crate::manifest::verify_runtime(&paths.versions().join("99.0.2")).is_ok());
    assert!(crate::install::repair(&paths, None).is_err());
    assert_eq!(activation_bytes(&paths), before);
    crate::install::repair(&paths, Some(&paths.versions().join("99.0.1"))).unwrap();
    assert_eq!(activation_bytes(&paths), before);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn healthy_legacy_uninstall_accepts_formatting_and_preserves_user_sections() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let projection_path = project.join(".generated/byo/projection-manifest.json");
    let mut projection = read_projection(&project).unwrap().unwrap();
    projection
        .managed_files
        .retain(|file| file.path != INTEGRITY_PATH);
    write_json(&projection_path, &projection).unwrap();
    std::fs::remove_file(project.join(INTEGRITY_PATH)).unwrap();
    let codex = project.join(".codex/config.toml");
    let text = std::fs::read_to_string(&codex).unwrap();
    std::fs::write(
        &codex,
        format!("customer=true\n{}", text.replace('\n', "\r\n")),
    )
    .unwrap();
    let agents = project.join("AGENTS.md");
    std::fs::write(
        &agents,
        format!(
            "customer notes\n{}",
            std::fs::read_to_string(&agents)
                .unwrap()
                .replace('\n', "\r\n")
        ),
    )
    .unwrap();
    uninstall_project(&project, &paths, false).unwrap();
    assert_eq!(
        std::fs::read_to_string(agents).unwrap().trim(),
        "customer notes"
    );
    assert!(std::fs::read_to_string(codex)
        .unwrap()
        .contains("customer=true"));
    assert!(project.join(".agent-workspace/PLAN.md").is_file());
    assert!(project_registry(&paths).unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
fn project_file_bytes(project: &Path) -> BTreeMap<String, Vec<u8>> {
    WalkDir::new(project)
        .into_iter()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| {
            (
                entry
                    .path()
                    .strip_prefix(project)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[cfg(feature = "development")]
#[test]
fn real_init_publication_errors_preserve_later_edits_and_restore_unedited_state() {
    use std::cell::RefCell;
    use std::rc::Rc;
    struct ResetBarrier;
    impl Drop for ResetBarrier {
        fn drop(&mut self) {
            PUBLICATION_BARRIER.with(|slot| *slot.borrow_mut() = None);
        }
    }
    for state in ["fresh", "capsule", "legacy"] {
        let existing = state == "capsule";
        let legacy = state == "legacy";
        for phase in ["before-registration", "after-registration"] {
            for edit in [false, true] {
                let (root, paths, project) = fixture();
                workspace(&paths, "0.1.8", false, "on-request");
                std::fs::write(project.join("AGENTS.md"), b"original customer text\n").unwrap();
                if existing {
                    init_project(&project, "firmware", false, false, &paths).unwrap();
                    // Harmless formatting forces a real shared-file publication.
                    let original = std::fs::read_to_string(project.join("AGENTS.md")).unwrap();
                    std::fs::write(project.join("AGENTS.md"), original.replace('\n', "\r\n"))
                        .unwrap();
                }
                if legacy {
                    std::fs::create_dir_all(project.join(".agent-workspace/specs")).unwrap();
                    std::fs::write(
                        project.join(".agent-workspace/PLAN.md"),
                        b"legacy user plan\n",
                    )
                    .unwrap();
                    std::fs::write(
                        project.join(".agent-workspace/HANDOFF.md"),
                        b"legacy user handoff\n",
                    )
                    .unwrap();
                    std::fs::write(
                        project.join(".agent-workspace/specs/user.md"),
                        b"legacy user spec\n",
                    )
                    .unwrap();
                }
                let edit_relative = if legacy {
                    ".agent-workspace/specs/later.md"
                } else {
                    "AGENTS.md"
                };
                let before = project_file_bytes(&project);
                let prior_registry = project_registry(&paths).unwrap();
                workspace(&paths, "0.1.9", false, "on-request");
                let editor = root.join("editor");
                native_runtime(&editor, "99.0.0", "");
                let editor = crate::install::launcher_path(&editor);
                let payload = root.join("editor-payload");
                let planned = Rc::new(RefCell::new(Vec::new()));
                let captured = planned.clone();
                let other = root.join("other-project").display().to_string();
                let other_for_hook = other.clone();
                let later = b"later customer edit\n".to_vec();
                let later_for_hook = later.clone();
                PUBLICATION_BARRIER.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move |current, project, paths| {
                        let publish = |target: &Path, bytes: &[u8]| -> Result<()> {
                            std::fs::write(&payload, bytes)?;
                            let output = std::process::Command::new(&editor)
                                .arg("edit")
                                .arg(target)
                                .arg(&payload)
                                .output()?;
                            anyhow::ensure!(
                                output.status.success(),
                                "editor failed: {}",
                                String::from_utf8_lossy(&output.stderr)
                            );
                            anyhow::ensure!(
                                std::fs::read(target)? == bytes,
                                "editor barrier did not publish bytes"
                            );
                            Ok(())
                        };
                        if current == "shared-published" {
                            *captured.borrow_mut() = std::fs::read(project.join("AGENTS.md"))?;
                            if edit {
                                publish(&project.join(edit_relative), &later_for_hook)?;
                            }
                        }
                        if current == phase {
                            let mut registry = project_registry(paths)?;
                            registry.insert("unrelated-project".into(), other_for_hook.clone());
                            publish(
                                &paths.state.join("projects.json"),
                                &serde_json::to_vec(&registry)?,
                            )?;
                            bail!("injected publication failure at {current}");
                        }
                        Ok(())
                    }))
                });
                let reset = ResetBarrier;
                let error = init_project(&project, "firmware", false, false, &paths).unwrap_err();
                drop(reset);
                assert!(format!("{error:#}").contains("injected publication failure"));
                let pending = project_backup_root(&paths, &project)
                    .unwrap()
                    .join("pending.json");
                if edit {
                    assert_eq!(std::fs::read(project.join(edit_relative)).unwrap(), later);
                    assert!(pending.is_file());
                    let record: PendingRefresh =
                        parse_project_json(&std::fs::read(&pending).unwrap()).unwrap();
                    assert!(pending.parent().unwrap().join(record.backup).is_dir());
                    // Explicit user recovery allows the same durable transaction
                    // to finish; the caught path has not pruned its needed data.
                    if legacy {
                        std::fs::remove_file(project.join(edit_relative)).unwrap();
                    } else {
                        std::fs::write(project.join("AGENTS.md"), &*planned.borrow()).unwrap();
                    }
                    let _lock = crate::install::InstallLock::acquire(&paths).unwrap();
                    recover_project_refresh(&project, &paths).unwrap();
                }
                assert_eq!(
                    project_file_bytes(&project),
                    before,
                    "state={state}, phase={phase}, edit={edit}"
                );
                assert!(!pending.exists());
                let mut expected = prior_registry;
                expected.insert("unrelated-project".into(), other.clone());
                assert_eq!(project_registry(&paths).unwrap(), expected);
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }
}

#[cfg(feature = "development")]
#[test]
fn public_project_mutations_and_lease_publication_share_install_lock() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let before = project_file_bytes(&project);
    let registry = std::fs::read(paths.state.join("projects.json")).unwrap();
    let lock = crate::install::InstallLock::acquire(&paths).unwrap();
    for error in [
        uninstall_project(&project, &paths, false).unwrap_err(),
        init_project(&project, "firmware", false, false, &paths).unwrap_err(),
    ] {
        assert!(format!("{error:#}").contains("another BYO installation mutation"));
    }
    assert!(crate::lease::RuntimeLeaseGuard::acquire(&paths, "0.1.8", "project").is_err());
    assert!(crate::global_doctor(&paths).is_err());
    assert_eq!(project_file_bytes(&project), before);
    assert_eq!(
        std::fs::read(paths.state.join("projects.json")).unwrap(),
        registry
    );
    // A caller already holding the lock publishes a lease without reacquiring.
    let lease = crate::lease::RuntimeLeaseGuard::acquire_locked(
        &paths,
        "0.1.8",
        &project_id(&project).unwrap(),
        &lock,
    )
    .unwrap();
    drop(lock);
    assert!(uninstall_project(&project, &paths, false).is_err());
    assert_eq!(project_file_bytes(&project), before);
    drop(lease);
    uninstall_project(&project, &paths, false).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn empty_product_failed_doctor_restores_absent_activation_files() {
    let (root, paths, _project) = fixture();
    let bad = root.join("bad");
    native_runtime(&bad, "99.0.1", "doctor");
    for repair in [false, true] {
        let result = if repair {
            crate::install::repair(&paths, Some(&paths.versions().join("99.0.1"))).map(|_| ())
        } else {
            crate::install::install_bundle(&bad, &paths).map(|_| ())
        };
        assert!(format!("{:#}", result.unwrap_err()).contains("fixture doctor failed"));
        assert!(!paths.current().exists());
        assert!(!paths.public_launcher().exists());
        assert!(!paths.install_locator().exists());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn legacy_uninstall_checks_all_shared_owned_sections_before_mutation() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.8", false, "on-request");
    init_project(&project, "firmware", false, false, &paths).unwrap();
    let mut projection = read_projection(&project).unwrap().unwrap();
    projection
        .managed_files
        .retain(|file| file.path != INTEGRITY_PATH);
    write_json(
        &project.join(".generated/byo/projection-manifest.json"),
        &projection,
    )
    .unwrap();
    std::fs::remove_file(project.join(INTEGRITY_PATH)).unwrap();
    let before = project_file_bytes(&project);
    let registry = std::fs::read(paths.state.join("projects.json")).unwrap();
    for relative in [
        "AGENTS.md",
        "CLAUDE.md",
        ".codex/config.toml",
        ".codex/hooks.json",
        ".mcp.json",
        ".claude/settings.json",
    ] {
        let original = std::fs::read_to_string(project.join(relative)).unwrap();
        let changed = if relative.ends_with(".json") {
            original
                .replace("byo hook ", "changed hook ")
                .replace("\"byo\"", "\"changed\"")
        } else if relative.ends_with(".toml") {
            original.replace("\"byo\"", "\"changed\"")
        } else {
            original.replace("BYO", "CHANGED")
        };
        assert_ne!(
            changed, original,
            "fixture must meaningfully edit {relative}"
        );
        std::fs::write(project.join(relative), &changed).unwrap();
        let error = uninstall_project(&project, &paths, false).unwrap_err();
        assert!(
            format!("{error:#}").contains("project-backups"),
            "{relative}: {error:#}"
        );
        let mut expected = before.clone();
        expected.insert(relative.into(), changed.into_bytes());
        assert_eq!(project_file_bytes(&project), expected);
        assert_eq!(
            std::fs::read(paths.state.join("projects.json")).unwrap(),
            registry
        );
        std::fs::write(project.join(relative), original).unwrap();
    }
    uninstall_project(&project, &paths, false).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "development")]
#[test]
fn review_legacy_archive_error_before_directory_recreation_restores_originals() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct ResetBarrier;
    impl Drop for ResetBarrier {
        fn drop(&mut self) {
            PUBLICATION_BARRIER.with(|slot| *slot.borrow_mut() = None);
        }
    }

    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.9", false, "on-request");
    std::fs::create_dir_all(project.join(".agent-workspace/specs")).unwrap();
    for (relative, bytes) in [
        (".agent-workspace/PLAN.md", b"customer plan\n".as_slice()),
        (
            ".agent-workspace/HANDOFF.md",
            b"customer handoff\n".as_slice(),
        ),
        (
            ".agent-workspace/specs/user.md",
            b"customer spec\n".as_slice(),
        ),
    ] {
        std::fs::write(project.join(relative), bytes).unwrap();
    }
    let before = project_file_bytes(&project);
    let prior_registry = project_registry(&paths).unwrap();
    let other = root.join("other-project").display().to_string();
    let other_for_hook = other.clone();
    let reached = Rc::new(Cell::new(false));
    let reached_for_hook = reached.clone();
    PUBLICATION_BARRIER.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |phase, project, paths| {
            if phase == "legacy-archived" {
                reached_for_hook.set(true);
                anyhow::ensure!(!project.join(".agent-workspace").exists());
                let mut registry = project_registry(paths)?;
                registry.insert("unrelated-project".into(), other_for_hook.clone());
                write_json(&paths.state.join("projects.json"), &registry)?;
                bail!("injected error immediately after legacy archive");
            }
            Ok(())
        }));
    });
    let reset = ResetBarrier;
    let error = init_project(&project, "firmware", false, false, &paths).unwrap_err();
    drop(reset);
    assert!(
        reached.get(),
        "test must exercise the actual archive boundary"
    );
    assert!(format!("{error:#}").contains("injected error immediately after legacy archive"));
    assert_eq!(project_file_bytes(&project), before);
    let pending = project_backup_root(&paths, &project)
        .unwrap()
        .join("pending.json");
    assert!(!pending.exists());
    let mut expected_registry = prior_registry;
    expected_registry.insert("unrelated-project".into(), other);
    assert_eq!(project_registry(&paths).unwrap(), expected_registry);
    {
        let _lock = crate::install::InstallLock::acquire(&paths).unwrap();
        recover_project_refresh(&project, &paths).unwrap();
    }
    assert_eq!(project_file_bytes(&project), before);
    std::fs::remove_dir_all(root).unwrap();
}

// This entry point exists only in the compiled test binary. The parent test
// passes a private fixture description to a fresh process; product builds have
// neither this environment input nor an interruption switch.
#[cfg(feature = "development")]
#[test]
fn legacy_archive_recovery_subprocess() {
    let Some(case_file) = std::env::var_os("BYO_B05_LEGACY_RECOVERY_CASE") else {
        return;
    };
    let case: serde_json::Value = parse_project_json(&std::fs::read(case_file).unwrap()).unwrap();
    let project = PathBuf::from(case["project"].as_str().unwrap());
    let paths: ProductPaths = serde_json::from_value(case["paths"].clone()).unwrap();
    match std::env::var("BYO_B05_LEGACY_RECOVERY_PHASE")
        .unwrap()
        .as_str()
    {
        "archive" => {
            let other = case["other"].as_str().unwrap().to_string();
            PUBLICATION_BARRIER.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |phase, project, paths| {
                    if phase == "legacy-archived" {
                        let missing = std::fs::symlink_metadata(project.join(".agent-workspace"))
                            .unwrap_err();
                        anyhow::ensure!(missing.kind() == std::io::ErrorKind::NotFound);
                        let pending = project_backup_root(paths, project)?.join("pending.json");
                        let record: PendingRefresh = parse_project_json(&std::fs::read(&pending)?)?;
                        anyhow::ensure!(record.legacy_workspace);
                        anyhow::ensure!(pending
                            .parent()
                            .unwrap()
                            .join(record.backup)
                            .join("legacy-agent-workspace")
                            .is_dir());
                        let mut registry = project_registry(paths)?;
                        registry.insert("unrelated-after-archive".into(), other.clone());
                        write_json(&paths.state.join("projects.json"), &registry)?;
                        // Abrupt process exit bypasses the caught-error rollback
                        // and all Rust destructors, leaving the real durable state.
                        std::process::exit(73);
                    }
                    Ok(())
                }))
            });
            let result = init_project(&project, "firmware", false, false, &paths);
            panic!("actual archive interruption barrier was not reached: {result:?}");
        }
        "recover" => {
            let _lock = crate::install::InstallLock::acquire(&paths).unwrap();
            // Enter recovery directly, before attempting to parse a capsule.
            recover_project_refresh(&project, &paths).unwrap();
        }
        phase => panic!("unexpected legacy recovery fixture phase {phase}"),
    }
}

#[cfg(feature = "development")]
#[test]
fn legacy_archive_interruption_recovers_real_journal_in_fresh_process() {
    let (root, paths, project) = fixture();
    workspace(&paths, "0.1.9", false, "on-request");
    std::fs::create_dir_all(project.join(".agent-workspace/specs")).unwrap();
    for (relative, bytes) in [
        (
            ".agent-workspace/PLAN.md",
            b"durable customer plan\n".as_slice(),
        ),
        (
            ".agent-workspace/HANDOFF.md",
            b"durable customer handoff\n".as_slice(),
        ),
        (
            ".agent-workspace/specs/user.md",
            b"durable customer spec\n".as_slice(),
        ),
    ] {
        std::fs::write(project.join(relative), bytes).unwrap();
    }
    let before = project_file_bytes(&project);
    let before_other = root.join("registered-before").display().to_string();
    write_json(
        &paths.state.join("projects.json"),
        &BTreeMap::from([("unrelated-before-archive", before_other.clone())]),
    )
    .unwrap();
    let other = root.join("registered-after").display().to_string();
    let case_file = root.join("legacy-recovery-case.json");
    write_json(
        &case_file,
        &serde_json::json!({"project":project, "paths":paths, "other":other}),
    )
    .unwrap();
    let child = |phase: &str| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "project::b05_lifecycle_tests::legacy_archive_recovery_subprocess",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BYO_B05_LEGACY_RECOVERY_CASE", &case_file)
            .env("BYO_B05_LEGACY_RECOVERY_PHASE", phase)
            .output()
            .unwrap()
    };
    let interrupted = child("archive");
    assert_eq!(
        interrupted.status.code(),
        Some(73),
        "{}",
        String::from_utf8_lossy(&interrupted.stderr)
    );
    assert_eq!(
        std::fs::symlink_metadata(project.join(".agent-workspace"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    let pending = project_backup_root(&paths, &project)
        .unwrap()
        .join("pending.json");
    let record: PendingRefresh = parse_project_json(&std::fs::read(&pending).unwrap()).unwrap();
    let archive = pending
        .parent()
        .unwrap()
        .join(&record.backup)
        .join("legacy-agent-workspace");
    for (relative, bytes) in &before {
        assert_eq!(
            std::fs::read(archive.join(relative.strip_prefix(".agent-workspace/").unwrap()))
                .unwrap(),
            *bytes
        );
    }
    // A later file at the missing directory's path must never be mistaken for
    // definite absence. Refusal retains both it and the real pending archive.
    std::fs::write(project.join(".agent-workspace"), b"later user text\n").unwrap();
    let refused = child("recover");
    assert!(!refused.status.success());
    assert_eq!(
        std::fs::read(project.join(".agent-workspace")).unwrap(),
        b"later user text\n"
    );
    assert!(pending.is_file());
    assert!(archive.is_dir());
    std::fs::remove_file(project.join(".agent-workspace")).unwrap();
    for _ in 0..2 {
        let recovered = child("recover");
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert_eq!(project_file_bytes(&project), before);
        assert!(!pending.exists());
        assert_eq!(
            project_registry(&paths).unwrap(),
            BTreeMap::from([
                ("unrelated-before-archive".into(), before_other.clone()),
                ("unrelated-after-archive".into(), other.clone()),
            ])
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
