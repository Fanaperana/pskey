import { useState, useEffect, useRef, useCallback } from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSeparator,
} from "@/components/ui/input-otp";
import { OTPInputContext } from "input-otp";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import React from "react";
import { cn } from "@/lib/utils";

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
        "relative flex size-5 items-center justify-center border-y border-r border-input text-[10px] transition-all outline-none first:rounded-l-sm first:border-l last:rounded-r-sm data-[active=true]:z-10 data-[active=true]:border-ring data-[active=true]:ring-1 data-[active=true]:ring-ring/50 dark:bg-input/30",
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
const PIN_LEN = 4;
const CHALLENGE_ROTATE_MS = 30_000;

/** Generate a 4-char challenge: 3 digits + 1 letter A-Z at a random slot. */
function generateChallenge(): string {
  const buf = new Uint32Array(5);
  crypto.getRandomValues(buf);
  const letterSlot = buf[0] % 4;
  const chars: string[] = [];
  for (let i = 0; i < 4; i++) {
    if (i === letterSlot) {
      chars.push(String.fromCharCode(65 + (buf[i + 1] % 26))); // A-Z
    } else {
      chars.push(String.fromCharCode(48 + (buf[i + 1] % 10))); // 0-9
    }
  }
  return chars.join("");
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
  const [unlockStatus, setUnlockStatus] = useState<
    "valid" | "invalid" | "busy" | null
  >(null);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [setupPin, setSetupPin] = useState("");
  const [challenge, setChallenge] = useState(() => generateChallenge());
  const [challengeExpiresAt, setChallengeExpiresAt] = useState(
    () => Date.now() + CHALLENGE_ROTATE_MS
  );
  const [challengeTick, setChallengeTick] = useState(0);

  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [actionPin, setActionPin] = useState("");
  const [actionStatus, setActionStatus] = useState<"valid" | "invalid" | null>(
    null
  );

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

  useEffect(() => {
    if (phase !== "unlocked") return;
    const iv = window.setInterval(() => {
      if (Date.now() >= expiresAt) doLock();
    }, 500);
    return () => window.clearInterval(iv);
  }, [phase, expiresAt, doLock]);

  useEffect(() => {
    if (!revealKey) return;
    const t = window.setTimeout(() => setRevealKey(null), 2000);
    return () => window.clearTimeout(t);
  }, [revealKey]);

  useEffect(() => {
    if (phase !== "setup" || setupPin.length !== PIN_LEN) return;
    setUnlockStatus("busy");
    invoke<UnlockResult>("vault_init", { pin: setupPin })
      .then((r) => {
        setUnlockStatus(null);
        setToken(r.token);
        setEntries(r.entries);
        setExpiresAt(Date.now() + r.expires_in_ms);
        setSetupPin("");
        setPhase("unlocked");
      })
      .catch((e) => {
        setUnlockStatus(null);
        setUnlockError(String(e));
        setSetupPin("");
      });
  }, [phase, setupPin]);

  useEffect(() => {
    if (phase !== "locked" || unlockPin.length !== PIN_LEN) return;
    setUnlockStatus("busy");
    invoke<UnlockResult>("vault_unlock_challenge", {
      input: { challenge, response: unlockPin.toUpperCase() },
    })
      .then((r) => {
        setUnlockStatus("valid");
        window.setTimeout(() => {
          setToken(r.token);
          setEntries(r.entries);
          setExpiresAt(Date.now() + r.expires_in_ms);
          setUnlockPin("");
          setUnlockStatus(null);
          setUnlockError(null);
          setPhase("unlocked");
        }, 200);
      })
      .catch((e) => {
        setUnlockStatus("invalid");
        setUnlockError(String(e));
        window.setTimeout(() => {
          setUnlockPin("");
          setUnlockStatus(null);
        }, 600);
      });
  }, [phase, unlockPin]);

  // Rotate the challenge every 30s (only while locked).
  useEffect(() => {
    if (phase !== "locked") return;
    const tickIv = window.setInterval(() => setChallengeTick((t) => t + 1), 1000);
    return () => window.clearInterval(tickIv);
  }, [phase]);
  useEffect(() => {
    if (phase !== "locked") return;
    if (Date.now() >= challengeExpiresAt) {
      setChallenge(generateChallenge());
      setChallengeExpiresAt(Date.now() + CHALLENGE_ROTATE_MS);
      setUnlockPin("");
      setUnlockStatus(null);
    }
  }, [phase, challengeTick, challengeExpiresAt]);
  // Fresh challenge whenever we enter the locked phase.
  useEffect(() => {
    if (phase === "locked") {
      setChallenge(generateChallenge());
      setChallengeExpiresAt(Date.now() + CHALLENGE_ROTATE_MS);
    }
  }, [phase]);

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
      setUnlockError(String(e));
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
      const msg = String(e);
      if (msg.includes("invalid pin")) {
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

  useEffect(() => {
    if (!pendingAction) return;
    if (actionPin.length !== PIN_LEN) {
      setActionStatus(null);
      return;
    }
    runAction(pendingAction, actionPin);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [actionPin]);

  const titleBar = (
    <div
      className="flex items-center justify-between px-2.5 py-1 border-b border-border/30"
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
        <span
          className="text-[10px] font-semibold text-muted-foreground tracking-widest uppercase"
          data-tauri-drag-region
        >
          PSKey
        </span>
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
              <Search className="size-3" />
            </Button>
            <Button
              variant="ghost"
              size="icon-xs"
              onClick={() => setView("settings")}
            >
              <Settings className="size-3" />
            </Button>
            <Button variant="ghost" size="icon-xs" onClick={doLock} title="Lock">
              <Lock className="size-3" />
            </Button>
          </>
        )}
        <Button
          variant="ghost"
          size="icon-xs"
          onClick={() => getCurrentWindow().close()}
        >
          <span className="text-xs leading-none">&times;</span>
        </Button>
      </div>
    </div>
  );

  const setupView = (
    <div className="px-2.5 py-3 flex flex-col items-center gap-2">
      <span className="text-[10px] font-semibold text-muted-foreground tracking-wider uppercase">
        Create Vault
      </span>
      <span className="text-[9px] text-muted-foreground text-center">
        Choose a 4-digit PIN.
        <br />
        Argon2id + libsodium.
      </span>
      <InputOTP
        maxLength={PIN_LEN}
        value={setupPin}
        onChange={setSetupPin}
        inputMode="numeric"
        pattern="[0-9]*"
        containerClassName="gap-1"
        autoFocus
      >
        <InputOTPGroup>
          <MaskedOTPSlot index={0} />
          <MaskedOTPSlot index={1} />
        </InputOTPGroup>
        <InputOTPSeparator />
        <InputOTPGroup>
          <MaskedOTPSlot index={2} />
          <MaskedOTPSlot index={3} />
        </InputOTPGroup>
      </InputOTP>
      {unlockError && (
        <span className="text-[9px] text-destructive">{unlockError}</span>
      )}
    </div>
  );

  const lockedView = (
    <div className="px-2.5 py-3 flex flex-col items-center gap-1.5">
      <span className="text-[10px] font-semibold text-muted-foreground tracking-wider uppercase">
        Unlock
      </span>
      {/* Challenge row (plaintext) */}
      <div className="flex items-center gap-1">
        <div className="flex gap-0.5 font-mono text-[11px] font-bold tracking-[0.15em]">
          {challenge.split("").map((c, i) => (
            <span
              key={i}
              className="flex size-5 items-center justify-center rounded-sm bg-muted/40 border border-border/40"
            >
              {c}
            </span>
          ))}
        </div>
      </div>
      <span className="text-[8px] text-muted-foreground">
        rotates in {Math.max(0, Math.ceil((challengeExpiresAt - Date.now()) / 1000))}s
      </span>
      <InputOTP
        maxLength={PIN_LEN}
        value={unlockPin}
        onChange={(v) => setUnlockPin(v.toUpperCase())}
        inputMode="text"
        pattern="[0-9A-Za-z]*"
        containerClassName="gap-1"
        autoFocus
      >
        <InputOTPGroup>
          <MaskedOTPSlot index={0} status={unlockStatus} />
          <MaskedOTPSlot index={1} status={unlockStatus} />
        </InputOTPGroup>
        <InputOTPSeparator />
        <InputOTPGroup>
          <MaskedOTPSlot index={2} status={unlockStatus} />
          <MaskedOTPSlot index={3} status={unlockStatus} />
        </InputOTPGroup>
      </InputOTP>
      {unlockError && (
        <span className="text-[9px] text-destructive text-center">
          {unlockError}
        </span>
      )}
    </div>
  );

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

  const settingsView = (
    <div className="flex flex-col items-center justify-center px-2.5 py-4 gap-1">
      <span className="text-[10px] text-muted-foreground">Encrypted with</span>
      <span className="text-[9px] font-semibold text-center">
        Argon2id +<br />XSalsa20-Poly1305
      </span>
      <Button size="xs" variant="outline" className="mt-2" onClick={doLock}>
        <Lock className="size-3 mr-1" />
        <span className="text-[10px]">Lock Now</span>
      </Button>
    </div>
  );

  const setPinView = (
    <div className="px-2.5 py-2 space-y-2 flex flex-col items-center">
      <span className="text-[10px] font-semibold text-muted-foreground tracking-wider uppercase">
        Set Item PIN
      </span>
      <span className="text-[9px] text-muted-foreground text-center">
        Choose a 4-digit PIN for
        <br />
        <span className="text-foreground">{newTitle || "this item"}</span>
      </span>
      <InputOTP
        maxLength={PIN_LEN}
        value={newCustomPin}
        onChange={setNewCustomPin}
        inputMode="numeric"
        pattern="[0-9]*"
        containerClassName="gap-1"
        autoFocus
      >
        <InputOTPGroup>
          <MaskedOTPSlot index={0} />
          <MaskedOTPSlot index={1} />
        </InputOTPGroup>
        <InputOTPSeparator />
        <InputOTPGroup>
          <MaskedOTPSlot index={2} />
          <MaskedOTPSlot index={3} />
        </InputOTPGroup>
      </InputOTP>
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
    <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 bg-background/95 backdrop-blur-sm">
      <span className="text-[9px] text-muted-foreground uppercase tracking-wider">
        Item PIN
      </span>
      <InputOTP
        maxLength={PIN_LEN}
        value={actionPin}
        onChange={setActionPin}
        inputMode="numeric"
        pattern="[0-9]*"
        containerClassName="gap-1"
        autoFocus
      >
        <InputOTPGroup>
          <MaskedOTPSlot index={0} status={actionStatus} />
          <MaskedOTPSlot index={1} status={actionStatus} />
        </InputOTPGroup>
        <InputOTPSeparator />
        <InputOTPGroup>
          <MaskedOTPSlot index={2} status={actionStatus} />
          <MaskedOTPSlot index={3} status={actionStatus} />
        </InputOTPGroup>
      </InputOTP>
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

  // Autolock on window blur
  useEffect(() => {
    if (phase !== "unlocked") return;
    const win = getCurrentWindow();
    const unlistenP = win.onFocusChanged(({ payload: focused }) => {
      if (!focused) doLock();
    });
    return () => {
      unlistenP.then((f) => f()).catch(() => {});
    };
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
      {phase === "setup" && setupView}
      {phase === "locked" && lockedView}
      {phase === "unlocked" && view === "list" && listView}
      {phase === "unlocked" && view === "add" && addView}
      {phase === "unlocked" && view === "settings" && settingsView}
      {phase === "unlocked" && view === "set-pin" && setPinView}
      {actionOverlay}
    </div>
  );
}

export default App;
