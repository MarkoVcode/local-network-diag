## What this changes

<!-- A sentence or two. Link the issue if there is one. -->

## Why

<!-- What problem does it solve? -->

## How it was verified

<!--
Which platform(s) did you test on? For parsing changes, please include the real
command output you tested against — that is what stops the fix regressing on
someone else's locale, OS version or hardware.
-->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass
- [ ] `cargo test --workspace` passes
- [ ] `npm run typecheck` and `npm run lint` pass
- [ ] Parsing changes include a test with captured real-world output
- [ ] Any new external-tool dependency has a matching check in `doctor.rs`
      stating what breaks without it and how to fix it per OS
- [ ] Still works without elevated privileges
