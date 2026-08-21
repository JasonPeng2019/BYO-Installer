# Windows global self-removal

Status: Proposed for the native-CI follow-up on 2026-08-20.

## Goal

Make `byo uninstall --global` remove the default Windows `%LOCALAPPDATA%\BYO`
root even though the command is executing `%LOCALAPPDATA%\BYO\bin\byo.exe`.
Keep the existing three-mode uninstall contract and the fail-closed project
preflight unchanged.

## Reproduction and root cause

Native CI run 32431073746 reproduced `Access is denied. (os error 5)` while
removing the Windows BYO data root. The install lock had already been released.
The remaining open object was the running public launcher: POSIX-style deletion
made its pathname disappear, but Windows retained the executable inside the BYO
directory until process exit, so synchronous removal of its ancestor failed.

## Design

When the Windows public launcher is nested inside a directory selected for
global purge, rename the launcher to a random tombstone beside that purge root
before deleting product directories. This keeps the live executable on the same
volume but outside every purge target. After the rename succeeds, use Windows'
POSIX delete disposition to remove the external tombstone pathname immediately;
the unnamed live image can finish outside the BYO directory being purged. If
that disposition is unavailable, a detached hidden `cmd.exe` helper deletes
only the exact tombstone after process exit. If the helper cannot start, restore
the launcher to its public path before returning an error. For layouts whose
launcher is not inside a purge root, retain the same POSIX/deferred
file-deletion path.

The tombstone must never be placed inside a purge target. Product directories
remain synchronously deleted, and the helper must not recursively delete a root;
that prevents a fast reinstall from being erased by delayed cleanup.

## Regression guard

- Extend the installed Windows acceptance flow to require the native
  `%LOCALAPPDATA%\BYO` root and its launcher tombstone to disappear after
  `uninstall --global`.
- Add Windows launcher tests for the evacuation-path selection and visible-path
  removal.
- Run Rust format, Clippy, and tests, then rerun the four-target native matrix.

## Documentation impact

The public command contract is unchanged: the README and installer guide
already promise full Windows application-data removal. This fix restores that
documented behavior. This spec and its review record the Windows implementation
detail without adding operator-facing flags or caveats.

## Verified

- Native CI reproduced the failure after the install-lock fix.
- The failing path is the default Windows data root containing the executing
  public launcher.
- Native CI run 32434293236 proved launcher evacuation releases and removes the
  complete `%LOCALAPPDATA%\BYO` root. It also exposed that starting the helper
  before the tombstone exists can exit without deleting the later rename.
- Native CI run 32436543644 again removed the complete BYO root after starting
  the helper after the rename, but the visible tombstone still outlived the
  ten-second acceptance window. The already-proven POSIX disposition is now the
  primary deletion mechanism after evacuation; deferred shell cleanup is only
  the compatibility fallback.

## Pending verification

- Windows unit and installed end-to-end proof after implementation.
- The complete native release matrix and final 0.1.3 artifact checks.
