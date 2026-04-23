# Contributing to PSKey

Thanks for your interest! PSKey is a tiny transparent Tauri widget password
manager — the scope is intentionally small, but contributions are welcome.

## Ground rules

- Be respectful. See the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Security comes first. If your change touches crypto, key handling, the
  vault file format, the session, or the challenge-response layer, please
  open an issue to discuss the design **before** writing code.
- Do not report security vulnerabilities in public issues — see
  [SECURITY.md](./SECURITY.md).

## Dev setup

```sh
pnpm install
pnpm tauri dev
```

Requirements:

- Node 20+
- pnpm (or use npm/yarn, but lockfile is pnpm)
- Rust stable toolchain
- Tauri v2 platform prerequisites: <https://v2.tauri.app/start/prerequisites/>

## Checks before you open a PR

```sh
npx tsc --noEmit              # TypeScript
cd src-tauri && cargo check   # Rust
cd src-tauri && cargo clippy  # Lints (if you have clippy installed)
```

## Commit style

- Prefer small, focused commits.
- Conventional-commits-ish prefixes are appreciated:
  `feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `chore:`, `build:`.
- Example: `feat(auth): rotate challenge every 30s`.

## Pull requests

1. Fork the repo and create a topic branch from `main`.
2. Keep the PR focused on a single concern.
3. Update `README.md` if user-facing behavior changes.
4. Make sure `tsc`, `cargo check`, and the app actually boots (`pnpm tauri dev`).
5. Open the PR and fill in the template.

## Areas where help is especially welcome

- Platform packaging (Linux / Windows builds, icons, signing).
- Accessibility of the tiny widget UI.
- Additional audit of the crypto / session / clipboard paths.
- Tests.

Thanks!
