# PSKey

Tiny transparent Tauri + React widget for storing passwords, backed by libsodium.

## Security model

- **Vault file**: `$APP_DATA/vault.bin`.
- **KDF**: Argon2id (libsodium `crypto_pwhash`, MODERATE ops/mem).
- **Cipher**: XSalsa20-Poly1305 (libsodium `secretbox`).
- **Plaintext**: msgpack-encoded `VaultData`.
- **Per-entry PIN**: separate Argon2id salt + 32-byte hash stored inside the
  encrypted blob. Verified with a constant-time compare.
- **Session**: 30s sliding TTL, opaque token held in Rust state.
- **Clipboard**: copy is performed in Rust and auto-cleared after 15s if the
  clipboard still contains our value.
- **Rate limit**: exponential backoff (base 2) after 3 failed unlocks.
- **Autolock**: on window blur and on session expiry.

## Challenge-response unlock

To protect the PIN against keyloggers and shoulder-surfing, PSKey uses a
rotating 4-character challenge shown above the OTP input on the unlock screen.
The user never types their raw PIN — they type a **response** computed per slot
from their memorised PIN and the current challenge.

- **Alphabet**: digits `0-9` and uppercase letters `A-Z`.
- **Challenge rotation**: every 30 seconds.
- **Layout**: 4 slots; the app currently generates 3 digits + 1 letter at a
  random position (to bound backend brute-force over the masked slot).

### Per-slot rule

For each slot *i* (1..4), given `challenge[i]` and the user's memorised
`pin_digit[i]` (0-9):

| `challenge[i]` | Response to type | Notes                                     |
| -------------- | ---------------- | ----------------------------------------- |
| digit `0-9`    | `base19(pin_digit[i] + challenge[i])` | sum is in `0..=18`          |
| letter `A-Z`   | `challenge[i]` itself                 | PIN digit at this slot is masked |

**Base-19 alphabet**: `0-9` → values 0-9, `A-I` → values 10-18.

### Examples

All four slots, combining the rules:

| challenge | pin  | response | explanation                                          |
| --------- | ---- | -------- | ---------------------------------------------------- |
| `9`       | `9`  | `I`      | `9+9 = 18 → I`                                       |
| `1`       | `9`  | `A`      | `1+9 = 10 → A`                                       |
| `2`       | `4`  | `6`      | `2+4 = 6`                                            |
| `I`       | `1`  | `I`      | letter challenge → type the letter                   |
| `X`       | `9`  | `X`      | letter challenge → PIN digit ignored for this slot   |

Walk-through: challenge `"29IX"`, PIN `"4187"`:

- slot 1: `'2' + 4 = 6`   → `6`
- slot 2: `'9' + 1 = 10`  → `A`
- slot 3: letter `'I'`    → `I`
- slot 4: letter `'X'`    → `X`

User types **`6AIX`** into the OTP.

### Verification

The frontend sends `(challenge, response)` to the backend
(`vault_unlock_challenge`). The backend:

1. Rejects any challenge containing more than 1 letter.
2. For each digit-challenge slot, recovers `pin_digit = (base19(response) − challenge) mod 19`,
   rejects anything outside `0..=9`.
3. For each letter-challenge slot, requires `response[i] == challenge[i]`
   (case-insensitive) and enumerates the 10 possible PIN digits.
4. Tries each candidate PIN (≤ 10 with the 1-letter cap) against the Argon2id
   vault key. On success, opens the session. Otherwise a **single** attempt is
   counted against the rate limiter regardless of how many candidates were
   tried.

## Dev

```sh
pnpm install
pnpm tauri dev
```

---

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
