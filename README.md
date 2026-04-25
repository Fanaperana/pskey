<div align="center">

<img src="public/hero.png" alt="PSKey" width="220" />

# 🔐 PSKey

**A tiny, transparent, always-on-top password manager widget.**
Built with [Tauri](https://tauri.app) + [React](https://react.dev) + [libsodium](https://doc.libsodium.org).

<br />

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Tauri](https://img.shields.io/badge/Tauri-2.x-24C8DB?style=flat-square&logo=tauri&logoColor=white)](https://tauri.app)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Rust](https://img.shields.io/badge/Rust-stable-DEA584?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![libsodium](https://img.shields.io/badge/crypto-libsodium-3B2D8F?style=flat-square)](https://doc.libsodium.org)
[![Argon2id](https://img.shields.io/badge/KDF-Argon2id-5A1F7A?style=flat-square)](https://en.wikipedia.org/wiki/Argon2)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square)](#)
[![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)](#)

<sub>145 px wide · transparent · draggable · autolocks on blur · 4-digit PIN with Base36 rolling challenge</sub>

</div>

---

## ✨ Highlights

- 🪟 **Tiny widget** — 145 px transparent floating window; drag it anywhere.
- 🔒 **Libsodium all the way down** — Argon2id + XSalsa20-Poly1305, nothing handrolled.
- 🎛️ **4-digit PIN, still hard to crack** — every Argon2id derivation also
  mixes in a 32-byte per-install **device secret** stored outside the vault
  file, so a stolen `vault.bin` alone is useless.
- 🎭 **Base36 rolling challenge** — the PIN you memorize is *never* what
  you type. A fresh 4-character `0-9A-Z` challenge rotates every 30 s and
  on every failed attempt; keystroke-only observers learn nothing reusable.
- 🔐 **Per-entry encryption** — entries with a custom PIN are sealed under
  a key derived from *that* PIN; unlocking the vault is not enough to
  reveal them.
- ⚡ **Async crypto** — every Argon2id call (unlock, add-entry, reveal,
  rekey) runs off the UI thread, with a cheeky "Cooking…" indicator.
- 🧊 **Autolock everywhere** — 30 s sliding session + instant lock on
  window blur (suspended while you're filling out a form).
- 📋 **Self-wiping clipboard** — copied secrets are cleared after 15 s.
- 🚫 **Persistent lockout** — escalating cooldowns (1 m → 24 h cap) survive
  process kill and reboot; first lockout costs 10 attempts, every one after
  that costs only 3.
- 🎨 **Themes & UI scale** — 5 dark variants and 6 zoom levels, persisted in
  `settings.json` (auto-generated with sane defaults).
- 🔑 **Rekey on demand** — change PIN and/or KDF strength
  (Interactive / Moderate / Sensitive) without re-entering data.
- 🗄️ **Forward-compatible vault** — magic v01 vaults auto-migrate to v02
  (device-secret-mixed) on first successful unlock.
- 🧱 **Hardened capabilities** — strict CSP, minimal Tauri permissions.

## 🔐 Security model

| Layer               | What                                                                |
| ------------------- | ------------------------------------------------------------------- |
| Vault file          | `$APP_DATA/vault.bin`, atomic write with `.bak` rotation            |
| Vault format        | `PSKEYv02` (current). `PSKEYv01` (PIN-only KDF) is read transparently and re-encrypted to v02 on first unlock |
| KDF                 | Argon2id via libsodium `crypto_pwhash`. Input is `pin \|\| device_secret`. Strength selectable per vault: Interactive ≈ 64 MiB, Moderate ≈ 256 MiB, Sensitive ≈ 1 GiB |
| Device secret       | 32 random bytes in `$APP_DATA/device_secret.bin` (mode `0600` on Unix). Mixed into every Argon2id derivation — a stolen `vault.bin` alone cannot be brute-forced even with a 4-digit PIN |
| Cipher              | XSalsa20-Poly1305 (libsodium `secretbox`)                           |
| Plaintext           | msgpack-encoded `VaultData`, zeroized on drop                       |
| Per-entry secrets   | passwords with a custom PIN are sealed in a `CustomSecret` block (separate Argon2id salt + nonce, key = `argon2id(custom_pin \|\| device_secret)`). Wrong PIN → secretbox MAC failure. No separate hash-and-compare step |
| Session             | 30 s sliding TTL, opaque 24-byte token held in Rust state only      |
| Clipboard           | copy performed in Rust, auto-cleared after 15 s if unchanged        |
| Rate limit          | persistent escalating lockout: 10 attempts → 1 m, 3 m, 5 m, 10 m, 15 m, 30 m, 1 h, 3 h, 12 h, 24 h cap; only **3** attempts between lockouts; resets on success |
| Autolock            | on window blur and on session expiry (suspended while a form / action overlay is open) |
| Front-end surface   | strict CSP, no remote assets, minimal Tauri capabilities            |

### What this defends against

- **Stolen `vault.bin`** (cloud sync, backup, mis-shared archive): without
  `device_secret.bin`, brute-forcing the 10⁴ PIN keyspace is infeasible —
  the effective work factor is 10⁴ × 2²⁵⁶.
- **Keystroke-only observers**: the rolling Base36 challenge means typed
  characters change every attempt; a recorded keystroke sequence cannot be
  replayed.
- **Idle / casual access** to an unlocked widget: window-blur and session-TTL
  autolock fire within seconds.
- **Brute-forcing through the UI**: persistent escalating lockout caps real
  attempts well below any meaningful coverage of a tiny PIN space.

### What it does **not** defend against

- An attacker who can read **both** `vault.bin` *and* `device_secret.bin`
  from your home directory — they have the full KDF input. Treat the device
  secret like an ssh private key. Hardware-backed storage (Secret Service /
  Keychain / DPAPI) is the natural follow-up.
- An attacker who sees **the screen and the keystrokes** simultaneously — the
  rolling challenge is a defence against keystroke-only capture, not against
  full screen recording.
- Malware running as your user: it can read clipboard, scrape memory after
  unlock, and key-log without restriction. PSKey is a userland tool.

## 🧩 Rolling challenge unlock

Your PIN is **4 digits** (`0-9`). To prevent keystroke-only observers from
recording a replayable PIN, the lock screen displays a **4-character Base36
challenge** (`0-9A-Z`) above the OTP input. You never type your raw PIN —
you type a **response** computed per slot from your memorized PIN and the
current challenge.

```text
  ┌───┐ ┌───┐ ┌───┐ ┌───┐
  │ 7 │ │ Z │ │ 5 │ │ 8 │   ← challenge (rotates every 30 s and on each fail)
  └───┘ └───┘ └───┘ └───┘
      PIN in your head: 1 2 3 4
  ┌───┐ ┌───┐ ┌───┐ ┌───┐
  │ 8 │ │ 1 │ │ 8 │ │ C │   ← what you actually type
  └───┘ └───┘ └───┘ └───┘
```

### Per-slot rule

For each slot *i* (1..4):

```text
response[i] = base36( ( pin_digit[i] + value(challenge[i]) ) mod 36 )
```

Base36 values: `0..9` → 0..9, `A` → 10, `B` → 11, …, `Z` → 35. Lowercase
input is auto-uppercased. The animated bar under the title bar drains over
the challenge's 30-second life and pulses red in the final seconds.

### Walk-through

Challenge `7Z58`, PIN `1234`:

| slot | PIN | challenge | value | sum | mod 36 | type |
| ---- | --- | --------- | ----- | --- | ------ | ---- |
|  1   |  1  |    `7`    |   7   |  8  |   8    | `8`  |
|  2   |  2  |    `Z`    |  35   | 37  |   1    | `1`  |
|  3   |  3  |    `5`    |   5   |  8  |   8    | `8`  |
|  4   |  4  |    `8`    |   8   | 12  |  12    | `C`  |

You type **`818C`** into the OTP. ✅

### Verification (backend)

The frontend sends `(challenge, response)` to `vault_unlock_challenge`. The
Rust backend:

1. Validates that both strings are 4 Base36 characters of equal length.
2. Reverses the math per slot:
   `pin_digit = (value(response[i]) − value(challenge[i])) mod 36`.
3. Rejects any decoded slot ≥ 10 as malformed (cannot match a real PIN) —
   **without** consuming a lockout attempt, so accidental letter typos in a
   digit slot don't burn through the rate limiter.
4. Runs **one** Argon2id derivation against the recovered PIN (no candidate
   enumeration, exactly one PIN per `(challenge, response)` pair).
5. On secretbox MAC failure, records a single attempt against the lockout
   schedule and rotates the challenge.

## 📁 App data layout

Everything PSKey writes lives under your platform's `$APP_DATA/com.fanaperana.pskey/`:

| File                | Purpose                                                                | Encrypted?       |
| ------------------- | ---------------------------------------------------------------------- | ---------------- |
| `vault.bin`         | secrets — header (KDF params + nonce) followed by `secretbox` blob     | yes              |
| `vault.bin.bak`     | one-step rollback of the previous good `vault.bin` (kept across writes) | yes (same key)  |
| `device_secret.bin` | 32 random bytes mixed into every Argon2id derivation (`0600` on Unix)  | no — keep it private |
| `settings.json`     | theme, UI scale, default KDF strength for new vaults                   | no (no secrets)  |
| `lockout.json`      | failed-attempt counter, current lockout level, cooldown deadline       | no (counters)    |

All non-vault files are auto-created with safe defaults on first launch and
written atomically (`*.tmp` → rename). **Back up `vault.bin` *and*
`device_secret.bin` together** — either one alone is unusable.

## 🚀 Getting started

```sh
pnpm install
pnpm tauri dev
```

Requirements:

- Node 20+ and pnpm
- Rust stable toolchain
- Tauri v2 prerequisites — <https://v2.tauri.app/start/prerequisites/>

### Build

```sh
pnpm tauri build
```

## 🧪 Checks

```sh
npx tsc --noEmit              # TypeScript
cd src-tauri && cargo check   # Rust
```

## 🗺️ Roadmap

- [ ] Linux / Windows packaging + icons
- [ ] Optional auto-update channel
- [ ] Import / export (encrypted)
- [ ] Tests for the vault format + challenge decoder
- [ ] Accessibility pass on the tiny widget UI

## 🐞 Troubleshooting

**`libpthread.so.0: undefined symbol: __libc_pthread_init` on Linux.**
This happens when WebKitGTK is launched from a Snap-installed VS Code: the
Snap leaks `GTK_PATH` / `XDG_DATA_DIRS` pointing into `/snap/...` which
load an incompatible glibc. Run `pnpm tauri dev` from a regular terminal
(or install VS Code from `.deb` / Flatpak / the official repo). If you must
launch from Snap, prefix the command with:

```sh
env -u GTK_PATH -u GTK_EXE_PREFIX -u GIO_MODULE_DIR -u GTK_IM_MODULE_FILE \
    -u XDG_DATA_DIRS -u XDG_DATA_HOME pnpm tauri dev
```

Open to ideas — see [CONTRIBUTING.md](CONTRIBUTING.md).

## 🤝 Contributing

PRs welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a PR. Security issues?
Report them privately via [SECURITY.md](SECURITY.md).

## 🧰 Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/)
  + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode)
  + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)

## 📜 License

[MIT](LICENSE) © 2026 Fanaperana
