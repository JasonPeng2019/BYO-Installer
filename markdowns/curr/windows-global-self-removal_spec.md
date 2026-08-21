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
volume but outside every purge target. After the rename succeeds, a detached
hidden Windows PowerShell helper waits on the exact launcher process object,
then deletes only the literal tombstone path with bounded retries. Do not use
POSIX delete disposition for this evacuated live image: Windows can make a
delete-pending executable temporarily invisible without completing removal,
which can skip the required post-exit helper. Waiting on the native process
object also prevents a live mapped image from making deletion report success
too early. If the helper cannot start, restore the launcher to its public path
before returning an error. For layouts whose launcher is not inside a purge
root, retain the same POSIX/deferred file-deletion path.

The tombstone must never be placed inside a purge target. Product directories
remain synchronously deleted, and the helper must not recursively delete a root;
that prevents a fast reinstall from being erased by delayed cleanup.

## Regression guard

- Extend the installed Windows acceptance flow to require the native
  `%LOCALAPPDATA%\BYO` root and its launcher tombstone to disappear after
  `uninstall --global`. Give the live-image tombstone the same bounded
  two-minute retry window as the product helper so transient Defender or
  antivirus handles do not create a false failure.
- Add Windows launcher tests for the evacuation-path selection and visible-path
  removal, including a copied test executable that schedules cleanup of its own
  running image and must disappear after it exits.
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
- Native CI run 32438855675 showed the POSIX disposition can still fall back on
  the hosted Windows filesystem, and exposed that Rust's standard argument
  quoting prevented the compound `cmd.exe /C` cleanup loop from executing.
  The helper now uses the Windows raw-argument API and has a direct Windows
  regression test.
- Native CI run 32441388047 passed that direct helper regression, including the
  raw compound command, but the installed E2E still applied its generic
  ten-second absence deadline to a helper designed to tolerate executable
  scanner locks for roughly two minutes. The installed assertion now exercises
  the product's actual bounded retry contract, and the direct helper regression
  uses a path containing spaces like the failed native install.
- Native CI run 32443769442 showed the tombstone still remained after the full
  retry window. Together with the passing direct helper test, this isolates the
  POSIX disposition shortcut: a live delete-pending image can appear absent and
  suppress helper startup without completing deletion. Evacuated launchers now
  always start the helper after the rename, and a live copied-executable test
  covers the exact lifecycle.
- Native CI run 32446143110 passed all non-Windows targets and the Windows
  build/archive contract, but the installed launcher still reappeared after the
  helper's full retry window. The helper could call `del` while the image was
  mapped, observe a transient success, and exit before the launcher process.
  Cleanup now waits for the exact parent PID before attempting deletion, and
  the Windows regression requires the copied live image to remain visible while
  its child is running and disappear after exit.
- Native CI run 32448738978 executed the new Windows regression before release
  packaging and proved that the embedded `tasklist | findstr` command pipeline
  never reached reliable post-exit deletion. The helper now uses PowerShell's
  process object with a bounded `WaitForExit`, followed by `-LiteralPath`
  deletion retries; no target path is interpolated into shell code.
- Native CI run 32449154544 passed both the regular-file helper test and the
  copied live-executable lifecycle in roughly three seconds. Its only Windows
  failure was the older placeholder evacuation assertion's two-second helper
  startup allowance; that bounded observation window is now ten seconds.
- Native CI run 32449345078 passed the Windows cleanup regressions, the native
  install without `HOME`, and complete launcher/application-root self-removal.
  The later cross-feature lease diagnostic check compared the Python 8.3 path
  spelling to Rust's canonical path as text. It now compares filesystem
  identity and always closes its MCP fixture in `finally`.
- Native CI run 32451135924 passed that lease diagnostic and reached the final
  global-uninstall receipt check, which contained the same valid canonical path
  under a different 8.3 spelling. The remaining receipt assertion now uses the
  shared filesystem-identity comparison as well.

- Native CI runs 32456547358 and 32532649977 still failed the installed E2E,
  but on the global-uninstall receipt's project-integration check for the
  Unicode project `firmware-µ-测试`, not launcher self-removal (which run
  32449345078 already proved). The launcher's registered canonical path and the
  test's `os.path.realpath` expectation name the same NTFS directory through
  case-fold-equivalent Mu codepoints — MICRO SIGN U+00B5 and GREEK SMALL LETTER
  MU U+03BC, which both uppercase to U+039C. `comparable_diagnostic_path` used
  `os.path.normcase` (a `str.lower()`), which does not unify them; it now
  case-folds after normcase so the receipt identity check honors Windows'
  case-insensitive path equivalence. The reproduced comparison was verified
  locally to fail before and pass after the change.

## Pending verification

- The complete native release matrix and final 0.1.3 artifact checks with the
  case-folded receipt comparison.
