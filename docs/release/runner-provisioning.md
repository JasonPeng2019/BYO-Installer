# Native and clean-machine runners

## Native build labels

- `macos-15` — GitHub-hosted Apple silicon.
- `macos-15-intel` — GitHub-hosted Intel.
- `windows-2025` — GitHub-hosted x86_64/MSVC.
- `byo-linux-x86_64-glibc-2.28` — ephemeral controlled image whose
  `getconf GNU_LIBC_VERSION` is exactly `glibc 2.28`.

The Linux label must not point at a newer host and merely claim compatibility.
Nuitka sidecars are built natively on every target.

## Clean-machine labels

- `byo-clean-macos-12-aarch64`
- `byo-clean-macos-12-x86_64`
- `byo-clean-windows-10-22h2-x86_64`
- `byo-clean-linux-x86_64-glibc-2.28`

Each job starts from a reverted VM snapshot, downloads the exact signed
candidate and test kit, has no source checkout or build/signing credentials,
and is destroyed or reverted afterward. Preserve only JUnit, signature,
receipt, hash, and uninstall evidence.

## HIL

There are no HIL runner labels. The remote physical HIL workflow was removed:
hardware, real-model and native-client acceptance run locally only, never on
GitHub Actions or self-hosted runners. `hil/README.md` describes the local bench
route, which uses the same reviewed fixtures and `run_hil.py` assertions.

Runner images must record OS build, compiler, Python, Rust, Nuitka, USB driver,
probe firmware, and image digest. Patch an image by producing a new immutable
image; do not mutate a release run in place.
