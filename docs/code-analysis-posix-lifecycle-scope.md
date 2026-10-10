# POSIX analysis cleanup scope

ROOT decision, 2026-10-10: the portability contract's process group and observed
descendant requirements mean the scope below. This decision follows independent
native review `pcrev/934c37e459434eaeb5924455bf3bba25`. Preserve the original
accepted contract and earlier review findings as evidence of their original scope.

For trusted managed Cppcheck, clangd and explicitly configured query drivers,
POSIX cleanup confirmation covers the original owned process group and
descendants acquired with exact ownership evidence, including those subsequently
detached. Success requires that no live process remains in that set and that the
direct child is reaped. An observed owned descendant with unavailable identity or
liveness, or an observation failure preventing proof of that set, makes cleanup
unconfirmed. Never-observed detached descendants remain `not_proven`; scoped
success does not assert their absence. Universal containment is outside this
portability contract. The tools execute trusted analyzer and query-driver inputs
under the caller's existing permissions.

A successfully spawned new-session direct child retained through authoritative
wait observation may use that exact child relationship as identity evidence when
its exited live metadata is unavailable. Missing birth tokens remain null and
grant no detached-process or recovery-marker signal authority. Early direct-child
exit alone does not invalidate scoped proof. A live or unknown child without
recoverable exact identity still causes an honest setup failure. An already
terminal child may return without a marker only after the covered group and
captured set are proven retired and the child is reaped.

Analysis receipts must name `coverage: retained_group_and_captured_descendants`,
`scope_confirmed`, and `unobserved_detached_descendants: not_proven`, while
retaining actual identities, exit/reap evidence, failures and cleanup timing.
An existing `confirmed` or `cleanup: confirmed` compatibility field means this
scope only; it cannot be the sole POSIX analysis success check. Probe and clangd
consumers retain the receipt on success and failure, including cached probes and
shutdown. Rust and the stdlib companion use the same scope. Public tool result
formats, Windows Jobs and hardware process behavior remain unchanged.

A bounded incomplete background observation can retry within the original
cleanup reserve. Actual denied access, unknown owned identity, failed wait/reap,
or missing/truncated terminal membership remains a failure. Final complete proof
must fit the unchanged deadline; an earlier partial snapshot cannot replace it.

Native GitHub Actions must check fast probes with delayed parent observation,
retained exit without live metadata, unavailable exact wait, original-group and
captured detached survivors, stale ancestry/PID reuse and unrelated peers,
permission failures, cancellation, EOF and shutdown. An independently observed
never-captured escape is a limitation control: retain `not_proven` and never
report universal cleanup. These checks, real analyzers and installed-product
evidence establish only their exact source and native host bytes.
