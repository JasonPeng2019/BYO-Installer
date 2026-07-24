# Native, clean-machine, and HIL runners

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

## HIL labels

- `byo-hil-macos-aarch64`
- `byo-hil-windows-x86_64`
- `byo-hil-linux-x86_64`

Each is a dedicated physical host with USB access, fixture power control
available as `byo-hil-power`, per-board locking, hard process timeouts, and no
production signing credentials. The repository variables
`BYO_HIL_PRIMARY_PROJECT` and `BYO_HIL_SACRIFICIAL_PROJECT` identify reviewed
fixture projects on those hosts.

Runner images must record OS build, compiler, Python, Rust, Nuitka, USB driver,
probe firmware, and image digest. Patch an image by producing a new immutable
image; do not mutate a release run in place.
