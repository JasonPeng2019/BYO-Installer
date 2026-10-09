Cppcheck common parity corpus

The project tree is relocatable: resolve directories from its root and files from each directory. Compare canonical paths after replacing the relocation root. Preserve argv order, spaces within arguments and optional output. Copy command-only.json to the selected compile_commands.json for the opaque quoted-command case. No shell execution is permitted.

expected.json defines scopes, strict config/database cases, flags and diagnostic states. XML files are synthetic failure controls derived from pinned Cppcheck 2.22 diagnostics; real Windows ARM proof is recorded separately. A clean XML report alone does not establish include coverage: the required flags always include missingInclude. purgedConfiguration describes identical code, rather than omitted distinct configurations; toomanyconfigs blocks.

manifest.json hashes every corpus file except itself. Rust parity must consume these inputs and report canonical path/run-directory substitutions; parity has not been established by this Python stage.
