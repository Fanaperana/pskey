# Security Policy

## Supported Versions

PSKey is pre-1.0 and under active development. Only the `main` branch is
supported — please make sure your report reproduces against the latest
commit before submitting.

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report vulnerabilities privately through GitHub's coordinated disclosure flow:

1. Go to <https://github.com/Fanaperana/pskey/security/advisories/new>
2. Describe the issue, reproduction steps, and impact.
3. Include a proposed fix or mitigation if you have one.

You should receive an initial response within a few days. If you do not, feel
free to ping the maintainer via a minimal public issue (without details)
asking them to check the advisory inbox.

## Scope

In-scope:

- The Rust backend (`src-tauri/`), including the vault file format, KDF,
  session handling, rate limiter, and clipboard handling.
- The challenge-response unlock layer.
- The CSP and Tauri capability configuration.
- Any code that touches plaintext secrets, keys, or PINs.

Out-of-scope:

- Attacks requiring a pre-compromised host (malicious OS, root, debugger
  attached, kernel keylogger, full disk access to RAM).
- Denial of service via resource exhaustion on the local machine.
- Social-engineering attacks against the user.

## Threat model (short form)

PSKey is designed to protect vault data at rest on a cooperating OS. It does
**not** claim to protect against:

- An attacker with live access to the process memory (no hardware enclave).
- Keyloggers running under the same user (the challenge-response layer only
  raises the bar against passive observers — not active key capture).
- A malicious display recorder that can see the challenge **and** the typed
  response (the challenge is not a secret; it is shown on screen).

## Disclosure

Once a fix lands, we will:

1. Publish a GitHub Security Advisory.
2. Credit the reporter (unless anonymity is requested).
3. Tag a release containing the fix.
