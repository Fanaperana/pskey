import { useState, useEffect, useRef, useCallback } from "react";
import React from "react";
import {
  Search,
  Plus,
  Copy,
  Eye,
  EyeOff,
  ArrowLeft,
  Settings,
  Check,
  Lock,
  Trash2,
  ChevronLeft,
  ChevronRight,
  ShieldX,
  TextCursorInput,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  InputOTP,
  InputOTPGroup,
} from "@/components/ui/input-otp";
import { OTPInputContext } from "input-otp";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import { cn } from "@/lib/utils";

interface EntryMeta {
  id: string;
  title: string;
  has_username: boolean;
  use_default_pin: boolean;
  has_custom_pin: boolean;
  created_at: number;
  updated_at: number;
}

interface UnlockResult {
  token: string;
  expires_in_ms: number;
  entries: EntryMeta[];
}

type Phase = "loading" | "setup" | "locked" | "unlocked";
type View = "list" | "add" | "settings" | "set-pin";

type PendingAction =
  | { kind: "reveal"; entryId: string; field: "password" | "username" }
  | { kind: "copy"; entryId: string; field: "password" | "username" }
  | { kind: "delete"; entryId: string };

const SESSION_TTL_MS = 30_000;
/// Fixed PIN length: a single group of 4 digits in the OTP UI. The 4-digit
/// keyspace is only safe because every Argon2id derivation also mixes in a
/// 32-byte device secret stored outside the vault file (`device_secret.bin`),
/// so a stolen vault file alone cannot be brute-forced.
const PIN_LEN = 4;
/// How often the rolling unlock challenge regenerates while the lock
/// screen is open. Each rotation also clears any partial response.
const CHALLENGE_ROTATE_MS = 30_000;

type Theme = "default" | "midnight" | "forest" | "mocha" | "rose";
const THEMES: { value: Theme; label: string }[] = [
  { value: "default", label: "Default" },
  { value: "midnight", label: "Midnight" },
  { value: "forest", label: "Forest" },
  { value: "mocha", label: "Mocha" },
  { value: "rose", label: "Rose" },
];
const SCALES: { value: number; label: string }[] = [
  { value: 0.9, label: "XS" },
  { value: 1.0, label: "S" },
  { value: 1.1, label: "M" },
  { value: 1.2, label: "L" },
  { value: 1.35, label: "XL" },
  { value: 1.5, label: "XXL" },
];

type KdfStrength = "interactive" | "moderate" | "sensitive";
const KDF_OPTIONS: { value: KdfStrength; label: string; hint: string }[] = [
  { value: "interactive", label: "Fast", hint: "Interactive · ~64 MiB" },
  { value: "moderate", label: "Balanced", hint: "Moderate · ~256 MiB" },
  { value: "sensitive", label: "Paranoid", hint: "Sensitive · ~1 GiB" },
];

interface SettingsPayload {
  theme: Theme;
  ui_scale: number;
  kdf_strength: KdfStrength;
}

const BUSY_PHRASES = [
  "Cooking",
  "Computing",
  "Fetching",
  "Crunching",
  "Whisking",
  "Brewing",
  "Hashing",
  "Churning",
  "Vibing",
  "Summoning",
  "Decrypting",
  "Unscrambling",
  "Untangling",
  "Mixing the salt",
  "Derivating",
  "Lockpicking",
  "Argon-ing",
  "Grinding",
  "Locking in",
  "Simmering",
  "Stirring the pot",
  "Baking",
  "Plotting",
  "Deciphering",
  "Mining bits",
  "Shuffling",
  "Calibrating",
  "Reticulating splines",
];

function pickBusyPhrase(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return BUSY_PHRASES[buf[0] % BUSY_PHRASES.length];
}

/// Backend errors come over Tauri's bridge as `{ kind, message }` objects
/// (see `error::CommandError` in Rust). Older code threw raw strings, so we
/// handle both shapes here.
type BackendError = { kind: string; message?: unknown } | string;
function errToText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const be = e as BackendError;
    if (typeof be === "object" && "kind" in be) {
      const msg =
        typeof be.message === "string" && be.message ? be.message : be.kind;
      return msg;
    }
  }
  return String(e);
}
function errKind(e: unknown): string | null {
  if (e && typeof e === "object" && "kind" in (e as object)) {
    return (e as { kind: string }).kind;
  }
  return null;
}

/// One slot of the masked PIN OTP grid. Renders a small box that shows a `∗`
/// when filled, mirrors active/caret state from input-otp's context, and
/// accepts a status colour for valid/invalid/busy feedback.
function MaskedOTPSlot({
  index,
  className,
  status,
  ...props
}: React.ComponentProps<"div"> & {
  index: number;
  status?: "valid" | "invalid" | "busy" | null;
}) {
  const ctx = React.useContext(OTPInputContext);
  const { char, hasFakeCaret, isActive } = ctx?.slots[index] ?? {};
  const statusClass =
    status === "valid"
      ? "border-green-500 ring-1 ring-green-500/40"
      : status === "invalid"
      ? "border-red-500 ring-1 ring-red-500/40"
      : status === "busy"
      ? "border-primary/60 ring-1 ring-primary/30 animate-pulse"
      : "";
  return (
    <div
      data-slot="input-otp-slot"
      data-active={isActive}
      className={cn(
        "relative flex size-5 items-center justify-center border-y border-r border-input text-[10px] transition-all outline-none first:rounded-l-[2px] first:border-l last:rounded-r-[2px] data-[active=true]:z-10 data-[active=true]:border-ring data-[active=true]:ring-1 data-[active=true]:ring-ring/50 dark:bg-input/30",
        statusClass,
        className
      )}
      {...props}
    >
      {char ? "∗" : null}
      {hasFakeCaret && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="h-3 w-px animate-caret-blink bg-foreground duration-1000" />
        </div>
      )}
    </div>
  );
}

/// Single 4-slot masked PIN field. Accepts Base36 chars (`0-9A-Z`) so the
/// challenge can rotate through the larger alphabet without changing the
/// user's underlying numeric PIN.
function PinOtp({
  value,
  onChange,
  status,
  autoFocus,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  status?: "valid" | "invalid" | "busy" | null;
  autoFocus?: boolean;
  disabled?: boolean;
}) {
  return (
    <InputOTP
      maxLength={PIN_LEN}
      value={value}
      onChange={(v) => onChange(v.toUpperCase())}
      inputMode="text"
      pattern="[0-9A-Za-z]*"
      containerClassName="gap-1"
      autoFocus={autoFocus}
      disabled={disabled}
    >
      <InputOTPGroup>
        <MaskedOTPSlot index={0} status={status} />
        <MaskedOTPSlot index={1} status={status} />
        <MaskedOTPSlot index={2} status={status} />
        <MaskedOTPSlot index={3} status={status} />
      </InputOTPGroup>
    </InputOTP>
  );
}

/// Generate a 4-character Base36 rolling challenge (`0-9A-Z`).
///
/// The user types
/// `response[i] = base36( (pin[i] + val(challenge[i])) mod 36 )`
/// per slot, so each unlock attempt produces different keystrokes for the
/// same underlying numeric PIN. The server reverses the math
/// deterministically — exactly one PIN candidate per attempt, so unlock
/// stays a single Argon2id derivation.
function generateChallenge(): string {
  const ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const buf = new Uint32Array(PIN_LEN);
  crypto.getRandomValues(buf);
  let s = "";
  for (let i = 0; i < PIN_LEN; i++) s += ALPHABET[buf[i] % 36];
  return s;
}

function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [view, setView] = useState<View>("list");
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState(0);
  const [entries, setEntries] = useState<EntryMeta[]>([]);
  const [search, setSearch] = useState("");
  const [currentIndex, setCurrentIndex] = useState(0);
  const [showSearch, setShowSearch] = useState(false);

  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [revealKey, setRevealKey] = useState<string | null>(null);

  const [newTitle, setNewTitle] = useState("");
  const [newHasUsername, setNewHasUsername] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newUseDefaultPin, setNewUseDefaultPin] = useState(false);
  const [newCustomPin, setNewCustomPin] = useState("");

  const [unlockPin, setUnlockPin] = useState("");
  const [unlockBusy, setUnlockBusy] = useState(false);
  const [unlockStatus, setUnlockStatus] = useState<
    "valid" | "invalid" | "busy" | null
  >(null);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [lockoutSecs, setLockoutSecs] = useState(0);
  const [lockoutLevel, setLockoutLevel] = useState(0);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [attemptThreshold, setAttemptThreshold] = useState(10);
  const [setupPin, setSetupPin] = useState("");
  const [challenge, setChallenge] = useState(() => generateChallenge());
  const [challengeExpiresAt, setChallengeExpiresAt] = useState(
    () => Date.now() + CHALLENGE_ROTATE_MS
  );
  const [busyPhrase, setBusyPhrase] = useState<string | null>(null);
  const [busyDots, setBusyDots] = useState(0);

  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [actionPin, setActionPin] = useState("");
  const [actionStatus, setActionStatus] = useState<"valid" | "invalid" | null>(
    null
  );
  const [actionBusy, setActionBusy] = useState(false);

  const [theme, setTheme] = useState<Theme>("default");
  const [uiScale, setUiScale] = useState<number>(1.2);
  const [kdfStrength, setKdfStrength] = useState<KdfStrength>("interactive");
  const [vaultStrength, setVaultStrength] = useState<KdfStrength | "unknown">(
    "unknown"
  );
  const [settingsLoaded, setSettingsLoaded] = useState(false);

  // Rekey dialog state.
  const [rekeyOpen, setRekeyOpen] = useState(false);
  const [rekeyCurrentPin, setRekeyCurrentPin] = useState("");
  const [rekeyNewPin, setRekeyNewPin] = useState("");
  const [rekeyTargetStrength, setRekeyTargetStrength] =
    useState<KdfStrength>("interactive");
  const [rekeyChangePin, setRekeyChangePin] = useState(false);
  const [rekeyBusy, setRekeyBusy] = useState(false);
  const [rekeyError, setRekeyError] = useState<string | null>(null);

  // Load persisted settings from settings.json on mount.
  useEffect(() => {
    invoke<SettingsPayload>("settings_get")
      .then((s) => {
        setTheme(s.theme);
        setUiScale(s.ui_scale);
        setKdfStrength(s.kdf_strength);
        setRekeyTargetStrength(s.kdf_strength);
      })
      .catch(() => {})
      .finally(() => setSettingsLoaded(true));
  }, []);

  // Apply theme class to <html>.
  useEffect(() => {
    const html = document.documentElement;
    THEMES.forEach((t) => html.classList.remove(`theme-${t.value}`));
    if (theme !== "default") html.classList.add(`theme-${theme}`);
  }, [theme]);

  // Apply UI scale via CSS zoom on <html>.
  useEffect(() => {
    (document.documentElement.style as unknown as { zoom: string }).zoom =
      String(uiScale);
  }, [uiScale]);

  // Persist to backend after initial load.
  useEffect(() => {
    if (!settingsLoaded) return;
    invoke("settings_set", {
      settingsInput: {
        theme,
        ui_scale: uiScale,
        kdf_strength: kdfStrength,
      },
    }).catch(() => {});
  }, [settingsLoaded, theme, uiScale, kdfStrength]);

  // After unlock, ask the backend what KDF strength the live vault uses.
  useEffect(() => {
    if (phase !== "unlocked" || !token) {
      setVaultStrength("unknown");
      return;
    }
    invoke<string>("vault_strength", { token })
      .then((s) => {
        const v = s as KdfStrength | "unknown";
        setVaultStrength(v);
        if (v !== "unknown") setRekeyTargetStrength(v);
      })
      .catch(() => setVaultStrength("unknown"));
  }, [phase, token]);

  // Pull lockout state from backend (also runs on mount so a cooldown
  // restored from disk is reflected immediately).
  const refreshLockout = useCallback(() => {
    return invoke<{
      remaining_secs: number;
      failed_attempts: number;
      lockout_level: number;
      threshold: number;
    }>("lockout_status")
      .then((s) => {
        setLockoutSecs(s.remaining_secs);
        setFailedAttempts(s.failed_attempts);
        setLockoutLevel(s.lockout_level);
        setAttemptThreshold(s.threshold);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshLockout();
  }, [refreshLockout]);

  // While locked, decrement the local counter every second so the UI shows a
  // live countdown without hammering the backend.
  useEffect(() => {
    if (lockoutSecs <= 0) return;
    const iv = window.setInterval(() => {
      setLockoutSecs((s) => {
        if (s <= 1) {
          window.setTimeout(() => refreshLockout(), 0);
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return () => window.clearInterval(iv);
  }, [lockoutSecs, refreshLockout]);

  const touchSession = useCallback(() => {
    setExpiresAt(Date.now() + SESSION_TTL_MS);
  }, []);

  const doLock = useCallback(() => {
    invoke("vault_lock").catch(() => {});
    setToken(null);
    setEntries([]);
    setRevealed({});
    setRevealKey(null);
    setView("list");
    setPendingAction(null);
    setActionPin("");
    setUnlockPin("");
    setPhase("locked");
  }, []);

  useEffect(() => {
    invoke<boolean>("vault_exists")
      .then((exists) => setPhase(exists ? "locked" : "setup"))
      .catch(() => setPhase("setup"));
  }, []);

  // Session TTL countdown — locks the vault when the timer runs out.
  // Skipped while the user is actively filling out a form (add/set-pin) or
  // an action overlay is open, since those flows can legitimately take
  // longer than the idle TTL and locking out mid-typing wipes their work.
  useEffect(() => {
    if (phase !== "unlocked") return;
    const inForm = view !== "list" || pendingAction !== null || rekeyOpen;
    const iv = window.setInterval(() => {
      if (inForm) {
        // Keep the session warm so we don't drop the moment the user finishes.
        touchSession();
        return;
      }
      if (Date.now() >= expiresAt) doLock();
    }, 500);
    return () => window.clearInterval(iv);
  }, [phase, expiresAt, doLock, view, pendingAction, rekeyOpen, touchSession]);

  useEffect(() => {
    if (!revealKey) return;
    const t = window.setTimeout(() => setRevealKey(null), 2000);
    return () => window.clearTimeout(t);
  }, [revealKey]);

  const submitSetup = useCallback(() => {
    if (phase !== "setup") return;
    if (setupPin.length !== PIN_LEN) {
      setUnlockError(`PIN must be ${PIN_LEN} digits`);
      return;
    }
    setUnlockStatus("busy");
    setUnlockError(null);
    setBusyPhrase(pickBusyPhrase());
    invoke<UnlockResult>("vault_init", { pin: setupPin })
      .then((r) => {
        setUnlockStatus(null);
        setBusyPhrase(null);
        setToken(r.token);
        setEntries(r.entries);
        setExpiresAt(Date.now() + r.expires_in_ms);
        setSetupPin("");
        setPhase("unlocked");
      })
      .catch((e) => {
        setUnlockStatus(null);
        setBusyPhrase(null);
        setUnlockError(errToText(e));
        setSetupPin("");
      });
  }, [phase, setupPin]);

  const submitUnlock = useCallback(() => {
    if (phase !== "locked") return;
    if (lockoutSecs > 0 || unlockBusy) return;
    if (unlockPin.length !== PIN_LEN) return;
    setUnlockBusy(true);
    setUnlockStatus("busy");
    setUnlockError(null);
    setBusyPhrase(pickBusyPhrase());
    // The user typed `response[i] = (pin[i] + challenge[i]) mod 10`. The
    // backend reverses that to recover the real PIN, so what was typed is
    // never the same twice for the same vault PIN.
    invoke<UnlockResult>("vault_unlock_challenge", {
      input: { challenge, response: unlockPin },
    })
      .then((r) => {
        setUnlockStatus("valid");
        setBusyPhrase(null);
        window.setTimeout(() => {
          setToken(r.token);
          setEntries(r.entries);
          setExpiresAt(Date.now() + r.expires_in_ms);
          setUnlockPin("");
          setUnlockStatus(null);
          setUnlockError(null);
          setUnlockBusy(false);
          setPhase("unlocked");
        }, 200);
        refreshLockout();
      })
      .catch((e) => {
        setUnlockStatus("invalid");
        setBusyPhrase(null);
        setUnlockError(errToText(e));
        // Rotate the challenge on a failed attempt so the next try has a
        // fresh code (also drops the partial response).
        setChallenge(generateChallenge());
        setChallengeExpiresAt(Date.now() + CHALLENGE_ROTATE_MS);
        window.setTimeout(() => {
          setUnlockPin("");
          setUnlockStatus(null);
          setUnlockBusy(false);
        }, 600);
        refreshLockout();
      });
  }, [phase, lockoutSecs, unlockBusy, unlockPin, challenge, refreshLockout]);

  // Auto-submit when the OTP is full. PIN is fixed-length (8 digits) so
  // this triggers once the last slot is filled.
  useEffect(() => {
    if (phase === "setup" && setupPin.length === PIN_LEN) {
      submitSetup();
    }
  }, [phase, setupPin, submitSetup]);
  useEffect(() => {
    if (
      phase === "locked" &&
      unlockPin.length === PIN_LEN &&
      !unlockBusy &&
      lockoutSecs === 0
    ) {
      submitUnlock();
    }
  }, [phase, unlockPin, unlockBusy, lockoutSecs, submitUnlock]);

  // Rotate the rolling challenge on a timer while the lock screen is open.
  useEffect(() => {
    if (phase !== "locked") return;
    const delay = Math.max(0, challengeExpiresAt - Date.now());
    const t = window.setTimeout(() => {
      setChallenge(generateChallenge());
      setChallengeExpiresAt(Date.now() + CHALLENGE_ROTATE_MS);
      setUnlockPin("");
      setUnlockStatus(null);
    }, delay);
    return () => window.clearTimeout(t);
  }, [phase, challengeExpiresAt]);

  // Fresh challenge whenever we (re)enter the locked phase.
  useEffect(() => {
    if (phase === "locked") {
      setChallenge(generateChallenge());
      setChallengeExpiresAt(Date.now() + CHALLENGE_ROTATE_MS);
    }
  }, [phase]);

  // Animate the "…" on the busy view.
  useEffect(() => {
    if (!busyPhrase) return;
    setBusyDots(0);
    const iv = window.setInterval(() => setBusyDots((d) => (d + 1) % 4), 250);
    return () => window.clearInterval(iv);
  }, [busyPhrase]);

  const filtered = entries.filter((e) =>
    e.title.toLowerCase().includes(search.toLowerCase())
  );
  useEffect(() => {
    if (currentIndex >= filtered.length && filtered.length > 0) {
      setCurrentIndex(filtered.length - 1);
    } else if (filtered.length === 0 && currentIndex !== 0) {
      setCurrentIndex(0);
    }
  }, [filtered.length, currentIndex]);
  const currentEntry =
    filtered.length > 0
      ? filtered[Math.min(currentIndex, filtered.length - 1)]
      : null;

  const resetAddForm = () => {
    setNewTitle("");
    setNewHasUsername(false);
    setNewUsername("");
    setNewPassword("");
    setNewUseDefaultPin(false);
    setNewCustomPin("");
  };

  const saveEntry = async (customPin?: string) => {
    if (!token) return;
    try {
      const meta = await invoke<EntryMeta>("add_entry", {
        token,
        input: {
          title: newTitle.trim(),
          has_username: newHasUsername,
          username: newHasUsername ? newUsername.trim() : "",
          password: newPassword,
          use_default_pin: newUseDefaultPin,
          custom_pin:
            !newUseDefaultPin && customPin && customPin.length > 0
              ? customPin
              : null,
        },
      });
      setEntries((prev) => [...prev, meta]);
      touchSession();
      resetAddForm();
      setView("list");
    } catch (e) {
      setUnlockError(errToText(e));
    }
  };

  const handleAdd = () => {
    if (!newTitle.trim() || !newPassword) return;
    if (!newUseDefaultPin) {
      setNewCustomPin("");
      setView("set-pin");
      return;
    }
    saveEntry();
  };

  const runAction = async (action: PendingAction, pin?: string) => {
    if (!token) return;
    setActionBusy(true);
    try {
      if (action.kind === "reveal") {
        const value = await invoke<string>(
          action.field === "password"
            ? "get_entry_secret"
            : "get_entry_username",
          action.field === "password"
            ? { token, id: action.entryId, pin: pin ?? null }
            : { token, id: action.entryId }
        );
        const key = `${action.entryId}-${action.field}`;
        setRevealed((r) => ({ ...r, [key]: value }));
        setRevealKey(key);
      } else if (action.kind === "copy") {
        await invoke("copy_to_clipboard", {
          token,
          id: action.entryId,
          field: action.field,
          pin: pin ?? null,
        });
      } else {
        await invoke("delete_entry", {
          token,
          id: action.entryId,
          pin: pin ?? null,
        });
        setEntries((prev) => prev.filter((e) => e.id !== action.entryId));
      }
      touchSession();
      setPendingAction(null);
      setActionPin("");
      setActionStatus(null);
    } catch (e) {
      const kind = errKind(e);
      if (kind === "invalid-pin" || errToText(e).includes("invalid pin")) {
        setActionStatus("invalid");
        window.setTimeout(() => {
          setActionPin("");
          setActionStatus(null);
        }, 600);
      } else {
        setPendingAction(null);
        setActionPin("");
        setActionStatus(null);
      }
    } finally {
      setActionBusy(false);
    }
  };

  const requestAction = (entry: EntryMeta, action: PendingAction) => {
    if (action.kind === "reveal") {
      const key = `${action.entryId}-${action.field}`;
      if (revealKey === key) {
        setRevealKey(null);
        return;
      }
    }
    const needsPin =
      entry.has_custom_pin &&
      (action.kind === "delete" ||
        (action.kind === "reveal" && action.field === "password") ||
        (action.kind === "copy" && action.field === "password"));
    if (needsPin) {
      setPendingAction(action);
      setActionPin("");
      setActionStatus(null);
      return;
    }
    runAction(action);
  };

  const submitActionPin = useCallback(() => {
    if (!pendingAction) return;
    if (actionPin.length === 0 || actionBusy) return;
    runAction(pendingAction, actionPin);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingAction, actionPin, actionBusy]);

  // Auto-submit the action PIN once all 8 digits are entered.
  useEffect(() => {
    if (pendingAction && actionPin.length === PIN_LEN && !actionBusy) {
      submitActionPin();
    }
  }, [pendingAction, actionPin, actionBusy, submitActionPin]);

  const titleBar = (
    <div
      className="relative flex items-center justify-between px-2.5 py-1 border-b border-border/30"
      data-tauri-drag-region
    >
      {phase === "unlocked" && view !== "list" ? (
        <Button
          variant="ghost"
          size="icon-xs"
          onClick={() => {
            if (view === "set-pin") {
              setNewCustomPin("");
              setView("add");
              return;
            }
            resetAddForm();
            setView("list");
          }}
        >
          <ArrowLeft className="size-3" />
        </Button>
      ) : (
        <TextCursorInput className="size-4" />
      )}
      {phase === "unlocked" && view !== "list" && (
        <span
          className="text-[10px] font-semibold text-muted-foreground tracking-widest uppercase"
          data-tauri-drag-region
        >
          {view === "settings"
            ? "Settings"
            : view === "add"
            ? "New"
            : view === "set-pin"
            ? "Set PIN"
            : ""}
        </span>
      )}
      <div className="flex gap-0.5">
        {phase === "unlocked" && view === "list" && (
          <>
            <Button
              variant="ghost"
              size="icon-xs"
              onClick={() => {
                setShowSearch((v) => {
                  if (v) setSearch("");
                  return !v;
                });
              }}
            >
              <Search className="size-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon-xs"
              onClick={() => setView("settings")}
            >
              <Settings className="size-4" />
            </Button>
            <Button variant="ghost" size="icon-xs" onClick={doLock} title="Lock">
              <Lock className="size-4" />
            </Button>
          </>
        )}
        <Button
          variant="ghost"
          size="icon-xs"
          onClick={() => getCurrentWindow().hide()}
        >
          <ShieldX className="size-4" />
        </Button>
      </div>
      {phase === "locked" && lockoutSecs === 0 && (
        // Two halves drain inward (left-anchored shrinks left, right-anchored
        // shrinks right) over CHALLENGE_ROTATE_MS, with a colour ramp from
        // green to red and a pulse in the final seconds. Re-keyed on every
        // challenge rotation so the animation restarts in lockstep.
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-px">
          <div
            className="absolute inset-x-0 top-0 h-px"
            style={{ backgroundColor: "hsl(140 35% 55% / 0.18)" }}
          />
          <div
            key={`challenge-left-${challengeExpiresAt}`}
            className="challenge-progress-left absolute left-0 top-0 h-px w-1/2"
            style={{ animationDuration: `${CHALLENGE_ROTATE_MS}ms` }}
          />
          <div
            key={`challenge-right-${challengeExpiresAt}`}
            className="challenge-progress-right absolute right-0 top-0 h-px w-1/2"
            style={{ animationDuration: `${CHALLENGE_ROTATE_MS}ms` }}
          />
        </div>
      )}
    </div>
  );

  const setupView = (
    <div className="px-2.5 py-3 flex flex-col items-center gap-2">
      <span className="text-[10px] font-semibold text-muted-foreground tracking-wider uppercase">
        Create Vault
      </span>
      <span className="text-[9px] text-muted-foreground text-center">
        Choose an {PIN_LEN}-digit PIN.
      </span>
      <PinOtp value={setupPin} onChange={setSetupPin} autoFocus />
      {unlockError && (
        <span className="text-[9px] text-destructive text-center">
          {unlockError}
        </span>
      )}
    </div>
  );

  const busyView = (
    <div className="px-2.5 py-5 flex flex-col items-center gap-2">
      <div className="flex gap-1">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className={cn(
              "size-1.5 rounded-full bg-primary transition-opacity",
              busyDots > i ? "opacity-100" : "opacity-25"
            )}
          />
        ))}
      </div>
      <span className="text-[10px] font-semibold text-foreground tracking-wide">
        {busyPhrase ?? "Working"}
        {".".repeat(busyDots)}
        <span className="opacity-0">{".".repeat(3 - busyDots)}</span>
      </span>
      <span className="text-[8px] text-muted-foreground">
        deriving key (Argon2id)
      </span>
    </div>
  );

  const lockedView = (() => {
    const isLocked = lockoutSecs > 0;
    const formatLock = (s: number) => {
      if (s >= 3600) {
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        return `${h}h ${m.toString().padStart(2, "0")}m ${sec
          .toString()
          .padStart(2, "0")}s`;
      }
      if (s >= 60) {
        const m = Math.floor(s / 60);
        const sec = s % 60;
        return `${m}:${sec.toString().padStart(2, "0")}`;
      }
      return `${s}s`;
    };
    const attemptsLeft = Math.max(0, attemptThreshold - failedAttempts);
    return (
      <div className="px-2.5 py-3 flex flex-col items-center gap-1.5">
        <span className="text-[10px] font-semibold text-muted-foreground tracking-wider uppercase">
          {isLocked ? "Locked Out" : "Unlock"}
        </span>
        {isLocked ? (
          <div className="flex flex-col items-center gap-1 py-2">
            <ShieldX className="size-6 text-destructive" />
            <span className="font-mono text-[14px] font-bold tracking-wider text-destructive">
              {formatLock(lockoutSecs)}
            </span>
            <span className="text-[8px] text-muted-foreground text-center leading-tight">
              Lockout #{lockoutLevel}
              <br />
              Next budget: {lockoutLevel >= 1 ? 3 : 10} attempts
            </span>
          </div>
        ) : (
          <>
            <div className="inline-flex">
              <div className="flex gap-0.5 font-mono text-[11px] font-bold tracking-[0.15em]">
                {challenge.split("").map((c, i) => (
                  <span
                    key={`${i}-${challengeExpiresAt}`}
                    className="flex size-5 items-center justify-center rounded-[2px] bg-muted/40 border border-border/40"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </div>
            <span className="text-[8px] text-muted-foreground text-center leading-tight">
              Type (PIN digit + char above) mod 36, in Base36 (0-9, A-Z).
            </span>
            <PinOtp
              value={unlockPin}
              onChange={setUnlockPin}
              status={unlockStatus}
              autoFocus
              disabled={unlockBusy}
            />
            {failedAttempts > 0 && (
              <span className="text-[8px] text-muted-foreground">
                {attemptsLeft} attempt{attemptsLeft === 1 ? "" : "s"} left
              </span>
            )}
            {unlockError && (
              <span className="text-[9px] text-destructive text-center">
                {unlockError}
              </span>
            )}
          </>
        )}
      </div>
    );
  })();

  const listView = (
    <>
      {showSearch && (
        <div className="border-b border-border/30">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 size-3 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              autoFocus
              className="w-full border border-input bg-transparent py-1 pl-7 pr-2 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </div>
        </div>
      )}

      <div>
        {currentEntry == null && (
          <div className="flex items-center justify-center py-4 text-[10px] text-muted-foreground">
            {entries.length === 0 ? "No entries yet" : "No match"}
          </div>
        )}
        {currentEntry && (
          <div
            key={currentEntry.id}
            className="px-2 py-1.5 space-y-1 border-b border-border/20"
          >
            <div className="text-[10px] font-medium truncate">
              {currentEntry.title}
            </div>

            {currentEntry.has_username && (
              <div className="flex items-center gap-1">
                <span className="text-[9px] text-muted-foreground w-5 shrink-0">
                  usr
                </span>
                <span className="text-[9px] flex-1 truncate">
                  {revealKey === `${currentEntry.id}-username`
                    ? revealed[`${currentEntry.id}-username`] ?? "••••••"
                    : "••••••"}
                </span>
                <Button
                  variant="ghost"
                  size="icon-xs"
                  className="size-4"
                  onClick={() =>
                    requestAction(currentEntry, {
                      kind: "reveal",
                      entryId: currentEntry.id,
                      field: "username",
                    })
                  }
                >
                  {revealKey === `${currentEntry.id}-username` ? (
                    <EyeOff className="size-2" />
                  ) : (
                    <Eye className="size-2" />
                  )}
                </Button>
                <Button
                  variant="ghost"
                  size="icon-xs"
                  className="size-4"
                  onClick={() =>
                    requestAction(currentEntry, {
                      kind: "copy",
                      entryId: currentEntry.id,
                      field: "username",
                    })
                  }
                >
                  <Copy className="size-2" />
                </Button>
              </div>
            )}

            <div className="flex items-center gap-1">
              <span className="text-[9px] text-muted-foreground w-5 shrink-0 flex items-center gap-0.5">
                psk
                {currentEntry.has_custom_pin && <Lock className="size-2" />}
              </span>
              <span className="text-[9px] flex-1 truncate">
                {revealKey === `${currentEntry.id}-password`
                  ? revealed[`${currentEntry.id}-password`] ?? "••••••"
                  : "••••••"}
              </span>
              <Button
                variant="ghost"
                size="icon-xs"
                className="size-4"
                onClick={() =>
                  requestAction(currentEntry, {
                    kind: "reveal",
                    entryId: currentEntry.id,
                    field: "password",
                  })
                }
              >
                {revealKey === `${currentEntry.id}-password` ? (
                  <EyeOff className="size-2" />
                ) : (
                  <Eye className="size-2" />
                )}
              </Button>
              <Button
                variant="ghost"
                size="icon-xs"
                className="size-4"
                onClick={() =>
                  requestAction(currentEntry, {
                    kind: "copy",
                    entryId: currentEntry.id,
                    field: "password",
                  })
                }
              >
                <Copy className="size-2" />
              </Button>
            </div>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between px-1.5 py-1 border-t border-border/30 gap-0.5">
        <span className="text-[9px] text-muted-foreground shrink-0">
          {filtered.length > 0
            ? `${Math.min(currentIndex, filtered.length - 1) + 1}/${filtered.length}`
            : `0/${entries.length}`}
        </span>
        <div className="flex gap-0.5">
          <Button
            variant="ghost"
            size="icon-xs"
            className="size-5"
            disabled={filtered.length < 2}
            onClick={() =>
              setCurrentIndex(
                (i) => (i - 1 + filtered.length) % filtered.length
              )
            }
          >
            <ChevronLeft className="size-3" />
          </Button>
          <Button
            variant="ghost"
            size="icon-xs"
            className="size-5"
            disabled={filtered.length < 2}
            onClick={() =>
              setCurrentIndex((i) => (i + 1) % filtered.length)
            }
          >
            <ChevronRight className="size-3" />
          </Button>
          <Button
            variant="ghost"
            size="icon-xs"
            className="size-5 text-destructive"
            disabled={!currentEntry}
            onClick={() =>
              currentEntry &&
              requestAction(currentEntry, {
                kind: "delete",
                entryId: currentEntry.id,
              })
            }
          >
            <Trash2 className="size-3" />
          </Button>
          <Button
            variant="ghost"
            size="icon-xs"
            className="size-5"
            onClick={() => setView("add")}
          >
            <Plus className="size-3" />
          </Button>
        </div>
      </div>
    </>
  );

  const addView = (
    <div className="px-1 pb-1 space-y-2 flex-1">
      <Input
        placeholder="Title"
        value={newTitle}
        onChange={(e) => setNewTitle(e.target.value)}
        className="h-6 text-[10px] px-2 rounded-sm"
      />
      <div className="flex items-stretch h-6 rounded-sm border border-input overflow-hidden focus-within:ring-1 focus-within:ring-ring">
        <label className="flex items-center justify-center px-1.5 border-r border-input bg-muted/30 cursor-pointer">
          <Checkbox
            checked={newHasUsername}
            onCheckedChange={(v) => setNewHasUsername(v === true)}
            className="size-3"
          />
        </label>
        <input
          type="text"
          placeholder="Username"
          value={newUsername}
          onChange={(e) => setNewUsername(e.target.value)}
          disabled={!newHasUsername}
          className="flex-1 min-w-0 bg-transparent px-2 text-[10px] outline-none placeholder:text-muted-foreground disabled:opacity-50"
        />
      </div>
      <div className="flex items-stretch h-6 rounded-sm border border-input overflow-hidden focus-within:ring-1 focus-within:ring-ring">
        <label className="flex items-center justify-center px-1.5 border-r border-input bg-muted/30">
          <Checkbox checked={true} disabled className="size-3" />
        </label>
        <input
          type="password"
          placeholder="Password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          autoComplete="new-password"
          className="flex-1 min-w-0 bg-transparent px-2 text-[10px] outline-none placeholder:text-muted-foreground"
        />
      </div>
      <label className="flex items-stretch h-6 rounded-sm border border-input overflow-hidden cursor-pointer">
        <div className="flex items-center justify-center px-1.5 border-r border-input bg-muted/30">
          <Checkbox
            checked={newUseDefaultPin}
            onCheckedChange={(v) => setNewUseDefaultPin(v === true)}
            className="size-3"
          />
        </div>
        <span className="flex-1 min-w-0 flex items-center px-2 text-[10px] text-muted-foreground">
          Default PIN
        </span>
      </label>
      <Button
        size="xs"
        className="w-full mt-1"
        onClick={handleAdd}
        disabled={!newTitle.trim() || !newPassword}
      >
        <Check className="size-3 mr-1" />
        <span className="text-[10px]">Save</span>
      </Button>
    </div>
  );

  const runRekey = useCallback(async () => {
    if (!token) return;
    if (rekeyCurrentPin.length !== PIN_LEN) {
      setRekeyError(`current PIN must be ${PIN_LEN} digits`);
      return;
    }
    if (rekeyChangePin && rekeyNewPin.length !== PIN_LEN) {
      setRekeyError(`new PIN must be ${PIN_LEN} digits`);
      return;
    }
    setRekeyBusy(true);
    setRekeyError(null);
    try {
      const r = await invoke<UnlockResult>("vault_rekey", {
        token,
        input: {
          current_pin: rekeyCurrentPin,
          new_pin: rekeyChangePin ? rekeyNewPin : null,
          strength: rekeyTargetStrength,
        },
      });
      setToken(r.token);
      setEntries(r.entries);
      setExpiresAt(Date.now() + r.expires_in_ms);
      setVaultStrength(rekeyTargetStrength);
      setRekeyOpen(false);
      setRekeyCurrentPin("");
      setRekeyNewPin("");
      setRekeyChangePin(false);
    } catch (e) {
      setRekeyError(errToText(e));
    } finally {
      setRekeyBusy(false);
    }
  }, [
    token,
    rekeyCurrentPin,
    rekeyNewPin,
    rekeyChangePin,
    rekeyTargetStrength,
  ]);

  const settingsView = (
    <div className="flex flex-col items-center justify-center px-2.5 py-3 gap-2">
      <div className="w-full flex flex-col gap-1">
        <label className="text-[9px] uppercase tracking-wider text-muted-foreground">
          Theme
        </label>
        <select
          value={theme}
          onChange={(e) => setTheme(e.target.value as Theme)}
          className="w-full text-[10px] bg-input/30 border border-input rounded-sm px-1.5 py-1 outline-none focus:ring-1 focus:ring-ring/50"
        >
          {THEMES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
      </div>
      <div className="w-full flex flex-col gap-1">
        <label className="text-[9px] uppercase tracking-wider text-muted-foreground">
          UI Scale
        </label>
        <select
          value={String(uiScale)}
          onChange={(e) => setUiScale(Number(e.target.value))}
          className="w-full text-[10px] bg-input/30 border border-input rounded-sm px-1.5 py-1 outline-none focus:ring-1 focus:ring-ring/50"
        >
          {SCALES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label} ({s.value}×)
            </option>
          ))}
        </select>
      </div>
      <div className="w-full flex flex-col gap-1">
        <label className="text-[9px] uppercase tracking-wider text-muted-foreground">
          KDF (new vaults)
        </label>
        <select
          value={kdfStrength}
          onChange={(e) => setKdfStrength(e.target.value as KdfStrength)}
          className="w-full text-[10px] bg-input/30 border border-input rounded-sm px-1.5 py-1 outline-none focus:ring-1 focus:ring-ring/50"
        >
          {KDF_OPTIONS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label} — {k.hint}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-col items-center mt-1 gap-0.5">
        <span className="text-[9px] text-muted-foreground">
          Vault: {vaultStrength === "unknown" ? "custom" : vaultStrength}
        </span>
        <span className="text-[9px] font-semibold text-center">
          Argon2id +<br />XSalsa20-Poly1305
        </span>
      </div>
      <div className="flex gap-1.5 mt-1">
        <Button
          size="xs"
          variant="outline"
          onClick={() => {
            setRekeyError(null);
            setRekeyCurrentPin("");
            setRekeyNewPin("");
            setRekeyChangePin(false);
            setRekeyOpen(true);
          }}
        >
          <span className="text-[10px]">Rekey</span>
        </Button>
        <Button size="xs" variant="outline" onClick={doLock}>
          <Lock className="size-3 mr-1" />
          <span className="text-[10px]">Lock</span>
        </Button>
      </div>
    </div>
  );

  const rekeyOverlay = rekeyOpen && (
    <div className="absolute inset-0 z-20 flex flex-col items-center justify-center gap-1.5 bg-background/95 backdrop-blur-sm px-2.5 py-3">
      <span className="text-[9px] text-muted-foreground uppercase tracking-wider">
        Rekey Vault
      </span>
      <div className="w-full flex flex-col gap-0.5">
        <label className="text-[8px] uppercase tracking-wider text-muted-foreground">
          Strength
        </label>
        <select
          value={rekeyTargetStrength}
          onChange={(e) =>
            setRekeyTargetStrength(e.target.value as KdfStrength)
          }
          className="w-full text-[10px] bg-input/30 border border-input rounded-sm px-1.5 py-1 outline-none"
          disabled={rekeyBusy}
        >
          {KDF_OPTIONS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label} — {k.hint}
            </option>
          ))}
        </select>
      </div>
      <span className="text-[8px] text-muted-foreground self-start">
        Current PIN
      </span>
      <PinOtp
        value={rekeyCurrentPin}
        onChange={setRekeyCurrentPin}
        autoFocus
        disabled={rekeyBusy}
      />
      <label className="flex items-center gap-1 text-[9px] text-muted-foreground self-start">
        <Checkbox
          checked={rekeyChangePin}
          onCheckedChange={(v) => setRekeyChangePin(Boolean(v))}
          disabled={rekeyBusy}
        />
        Change PIN too
      </label>
      {rekeyChangePin && (
        <PinOtp
          value={rekeyNewPin}
          onChange={setRekeyNewPin}
          disabled={rekeyBusy}
        />
      )}
      {rekeyError && (
        <span className="text-[9px] text-red-500 text-center">
          {rekeyError}
        </span>
      )}
      <div className="flex gap-1.5 mt-0.5">
        <Button
          size="xs"
          onClick={runRekey}
          disabled={rekeyBusy || rekeyCurrentPin.length !== PIN_LEN}
        >
          <span className="text-[10px]">
            {rekeyBusy ? "Working…" : "Apply"}
          </span>
        </Button>
        <Button
          size="xs"
          variant="outline"
          onClick={() => setRekeyOpen(false)}
          disabled={rekeyBusy}
        >
          <span className="text-[10px]">Cancel</span>
        </Button>
      </div>
    </div>
  );

  const setPinView = (
    <div className="px-2.5 py-2 space-y-2 flex flex-col items-center">
      <span className="text-[10px] font-semibold text-muted-foreground tracking-wider uppercase">
        Set Item PIN
      </span>
      <span className="text-[9px] text-muted-foreground text-center">
        {PIN_LEN}-digit PIN for
        <br />
        <span className="text-foreground">{newTitle || "this item"}</span>
      </span>
      <PinOtp value={newCustomPin} onChange={setNewCustomPin} autoFocus />
      <Button
        size="xs"
        className="w-full mt-1"
        onClick={() => saveEntry(newCustomPin)}
        disabled={newCustomPin.length !== PIN_LEN}
      >
        <Check className="size-3 mr-1" />
        <span className="text-[10px]">Save</span>
      </Button>
    </div>
  );

  const actionOverlay = pendingAction && (
    <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 bg-background/95 backdrop-blur-sm px-2.5">
      <span className="text-[9px] text-muted-foreground uppercase tracking-wider">
        Item PIN
      </span>
      <PinOtp
        value={actionPin}
        onChange={setActionPin}
        status={actionStatus}
        autoFocus
        disabled={actionBusy}
      />
      <button
        onClick={() => {
          setPendingAction(null);
          setActionPin("");
          setActionStatus(null);
        }}
        className="text-[9px] text-muted-foreground hover:text-foreground"
      >
        cancel
      </button>
    </div>
  );

  // Dynamic window sizing
  const rootRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;
    const DURATION = 180;
    const easeOutCubic = (t: number) => 1 - Math.pow(1 - t, 3);
    let rafId = 0;
    let animStart = 0;
    let fromW = 0;
    let fromH = 0;
    let targetW = 0;
    let targetH = 0;
    let currentW = 0;
    let currentH = 0;
    let initialized = false;
    const tick = (now: number) => {
      const t = Math.min(1, (now - animStart) / DURATION);
      const k = easeOutCubic(t);
      const w = Math.round(fromW + (targetW - fromW) * k);
      const h = Math.round(fromH + (targetH - fromH) * k);
      if (w !== currentW || h !== currentH) {
        currentW = w;
        currentH = h;
        getCurrentWindow()
          .setSize(new LogicalSize(w, h))
          .catch(() => {});
      }
      if (t < 1) rafId = requestAnimationFrame(tick);
      else rafId = 0;
    };
    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (!rect) return;
      const w = Math.ceil(rect.width);
      const h = Math.ceil(rect.height);
      if (w <= 0 || h <= 0) return;
      if (!initialized) {
        initialized = true;
        currentW = w;
        currentH = h;
        targetW = w;
        targetH = h;
        getCurrentWindow()
          .setSize(new LogicalSize(w, h))
          .catch(() => {});
        return;
      }
      if (w === targetW && h === targetH) return;
      targetW = w;
      targetH = h;
      fromW = currentW;
      fromH = currentH;
      animStart = performance.now();
      if (!rafId) rafId = requestAnimationFrame(tick);
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, []);

  // Autolock on window blur — but only from the entry list. While the user
  // is in a transient view (add/set-pin/settings/rekey/action overlay)
  // losing focus shouldn't wipe their in-progress input. The session TTL
  // still applies once they're back on the list.
  useEffect(() => {
    if (phase !== "unlocked") return;
    if (view !== "list" || pendingAction !== null || rekeyOpen) return;
    const win = getCurrentWindow();
    const unlistenP = win.onFocusChanged(({ payload: focused }) => {
      if (!focused) doLock();
    });
    return () => {
      unlistenP.then((f) => f()).catch(() => {});
    };
  }, [phase, view, pendingAction, rekeyOpen, doLock]);

  // Tray-triggered lock ("vault://locked" event from Rust).
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen("vault://locked", () => {
          if (phase === "unlocked") doLock();
        })
      )
      .then((u) => {
        unlisten = u;
      })
      .catch(() => {});
    return () => unlisten?.();
  }, [phase, doLock]);

  return (
    <div
      ref={rootRef}
      className="relative w-[145px] overflow-hidden rounded-md border border-border/30 bg-background shadow-2xl flex flex-col"
      data-tauri-drag-region
    >
      {titleBar}
      {phase === "loading" && (
        <div className="py-4 text-center text-[9px] text-muted-foreground">
          …
        </div>
      )}
      {phase === "setup" && (busyPhrase ? busyView : setupView)}
      {phase === "locked" && (busyPhrase ? busyView : lockedView)}
      {phase === "unlocked" && view === "list" && listView}
      {phase === "unlocked" && view === "add" && addView}
      {phase === "unlocked" && view === "settings" && settingsView}
      {phase === "unlocked" && view === "set-pin" && setPinView}
      {actionOverlay}
      {rekeyOverlay}
    </div>
  );
}

export default App;
