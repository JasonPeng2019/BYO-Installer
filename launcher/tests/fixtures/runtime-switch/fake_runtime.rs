// Native executable contract fixture, not a product sidecar or second bundle.
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("hold") {
        std::fs::write(&args[2], b"ready").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut runtime = executable.parent().unwrap().to_path_buf();
    if args.get(1).map(String::as_str) == Some("doctor") {
        let root = PathBuf::from(std::env::var_os("BYO_HOME").expect("explicit product home"));
        let current = std::fs::read_to_string(root.join("data/current.json")).unwrap();
        let version = current
            .split("\"version\": \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        runtime = root.join("data/versions").join(version);
    } else if runtime.file_name().unwrap() == "sidecar" {
        runtime.pop();
    }
    let identity = std::fs::read_to_string(runtime.join("runtime-test-identity")).unwrap();
    let mut fields = identity.lines();
    let version = fields.next().unwrap();
    let failure = fields.next().unwrap_or("");
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("byo {version}");
        return;
    }
    if args.get(1).map(String::as_str) == Some("doctor") {
        if failure == "doctor" {
            eprintln!("fixture doctor failed");
            std::process::exit(1);
        }
        println!("[]");
        return;
    }
    let expected = args
        .windows(2)
        .find(|pair| pair[0] == "--launcher-version")
        .unwrap();
    if expected[1] != version
        || (failure == "activation" && runtime.parent().unwrap().file_name().unwrap() == "versions")
    {
        eprintln!("fixture sidecar rejected version or activation");
        std::process::exit(1);
    }
    let protocol = if failure == "protocol" { 2 } else { 1 };
    println!("{{\"status\":\"passed\",\"sidecar_protocol\":1,\"worker_protocol\":{protocol},\"workflow_protocol\":1,\"capsule_schema\":1,\"project_state_schema\":1,\"runtime_manifest_verified\":true,\"version\":\"{version}\"}}");
}
