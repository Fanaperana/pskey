import { useState, useEffect, useRef } from "react";
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
import React from "react";
import { cn } from "@/lib/utils";

function MaskedOTPSlot({
  index,
  className,
  status,
  ...props
}: React.ComponentProps<"div"> & {
  index: number;
  status?: "valid" | "invalid" | null;
}) {
  const ctx = React.useContext(OTPInputContext);
  const { char, hasFakeCaret, isActive } = ctx?.slots[index] ?? {};
  const statusClass =
    status === "valid"
      ? "border-green-500 ring-1 ring-green-500/40"
      : status === "invalid"
      ? "border-red-500 ring-1 ring-red-500/40"
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

interface PasswordEntry {
  id: string;
  title: string;
  hasUsername: boolean;
  username: string;
  password: string;
  useDefaultPin: boolean;
  customPin?: string;
}

type View = "list" | "add" | "settings" | "set-pin";

function App() {
  const [view, setView] = useState<View>("list");
  const [entries, setEntries] = useState<PasswordEntry[]>([]);
  const [search, setSearch] = useState("");
  const [revealField, setRevealField] = useState<string | null>(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [showSearch, setShowSearch] = useState(false);

  // Auto-hide revealed field after 2s
  useEffect(() => {
    if (!revealField) return;
    const t = window.setTimeout(() => setRevealField(null), 2000);
    return () => window.clearTimeout(t);
  }, [revealField]);

  // Add form state
  const [newTitle, setNewTitle] = useState("");
  const [newHasUsername, setNewHasUsername] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newUseDefaultPin, setNewUseDefaultPin] = useState(false);
  const [newCustomPin, setNewCustomPin] = useState("");

  // Settings state
  const [globalPin, setGlobalPin] = useState("");

  // Unlock state
  const UNLOCK_COOLDOWN_MS = 30_000;
  const [unlockedUntil, setUnlockedUntil] = useState(0);
  const [pendingAction, setPendingAction] = useState<
    | { kind: "reveal"; entryId: string }
    | { kind: "copy"; value: string }
    | { kind: "delete"; entryId: string }
    | null
  >(null);
  const [pinInput, setPinInput] = useState("");
  const [pinStatus, setPinStatus] = useState<"valid" | "invalid" | null>(null);
  const [expectedPin, setExpectedPin] = useState("");
  const pinResetRef = useRef<number | null>(null);

  const isUnlocked = () => Date.now() < unlockedUntil;

  const requestPasswordAction = (
    entry: PasswordEntry,
    action:
      | { kind: "reveal"; entryId: string }
      | { kind: "copy"; value: string }
      | { kind: "delete"; entryId: string }
  ) => {
    // Figure out which PIN (if any) guards this action.
    // Delete uses whatever PIN guards the item, or global PIN as fallback.
    let pin = "";
    if (entry.useDefaultPin) {
      pin = globalPin;
    } else if (entry.customPin) {
      pin = entry.customPin;
    } else if (action.kind === "delete") {
      pin = globalPin;
    }
    if (!pin || isUnlocked()) {
      executeAction(action);
      return;
    }
    setExpectedPin(pin);
    setPendingAction(action);
    setPinInput("");
    setPinStatus(null);
  };

  const executeAction = (
    action:
      | { kind: "reveal"; entryId: string }
      | { kind: "copy"; value: string }
      | { kind: "delete"; entryId: string }
  ) => {
    if (action.kind === "reveal") {
      setRevealField(
        revealField === `${action.entryId}-psk` ? null : `${action.entryId}-psk`
      );
    } else if (action.kind === "copy") {
      navigator.clipboard.writeText(action.value);
    } else {
      setEntries((prev) => prev.filter((e) => e.id !== action.entryId));
    }
  };

  const cancelUnlock = () => {
    setPendingAction(null);
    setPinInput("");
    setPinStatus(null);
    if (pinResetRef.current) {
      window.clearTimeout(pinResetRef.current);
      pinResetRef.current = null;
    }
  };

  // Validate PIN as user types
  useEffect(() => {
    if (!pendingAction) return;
    if (pinInput.length < expectedPin.length) {
      setPinStatus(null);
      return;
    }
    if (pinInput === expectedPin) {
      setPinStatus("valid");
      const action = pendingAction;
      pinResetRef.current = window.setTimeout(() => {
        setUnlockedUntil(Date.now() + UNLOCK_COOLDOWN_MS);
        executeAction(action);
        setPendingAction(null);
        setPinInput("");
        setPinStatus(null);
      }, 250);
    } else {
      setPinStatus("invalid");
      pinResetRef.current = window.setTimeout(() => {
        setPinInput("");
        setPinStatus(null);
      }, 600);
    }
    return () => {
      if (pinResetRef.current) {
        window.clearTimeout(pinResetRef.current);
        pinResetRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pinInput, pendingAction, expectedPin]);

  const filtered = entries.filter(
    (e) =>
      e.title.toLowerCase().includes(search.toLowerCase()) ||
      e.username.toLowerCase().includes(search.toLowerCase())
  );

  // Clamp currentIndex when list changes
  useEffect(() => {
    if (currentIndex >= filtered.length && filtered.length > 0) {
      setCurrentIndex(filtered.length - 1);
    } else if (filtered.length === 0 && currentIndex !== 0) {
      setCurrentIndex(0);
    }
  }, [filtered.length, currentIndex]);

  const currentEntry =
    filtered.length > 0 ? filtered[Math.min(currentIndex, filtered.length - 1)] : null;
  const displayed = currentEntry ? [currentEntry] : [];

  const resetAddForm = () => {
    setNewTitle("");
    setNewHasUsername(false);
    setNewUsername("");
    setNewPassword("");
    setNewUseDefaultPin(false);
    setNewCustomPin("");
  };

  const commitEntry = (customPin?: string) => {
    const entry: PasswordEntry = {
      id: crypto.randomUUID(),
      title: newTitle.trim(),
      hasUsername: newHasUsername,
      username: newHasUsername ? newUsername.trim() : "",
      password: newPassword,
      useDefaultPin: newUseDefaultPin,
      customPin: newUseDefaultPin ? undefined : customPin,
    };
    setEntries((prev) => [...prev, entry]);
    resetAddForm();
    setView("list");
  };

  const handleAdd = () => {
    if (!newTitle.trim()) return;
    if (!newUseDefaultPin) {
      // Need a per-item PIN — go to set-pin view
      setNewCustomPin("");
      setView("set-pin");
      return;
    }
    commitEntry();
  };

  const titleBar = (
    <div
      className="flex items-center justify-between px-2.5 py-1 border-b border-border/30"
      data-tauri-drag-region
    >
      {view !== "list" ? (
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
      {view !== "list" && (
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
        {view === "list" && (
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

  // ─── LIST VIEW ───
  const listView = (
    <>
      {/* Search (toggleable) */}
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

      {/* Single displayed item */}
      <div>
        {displayed.length === 0 && (
          <div className="flex items-center justify-center py-4 text-[10px] text-muted-foreground">
            {entries.length === 0 ? "No entries yet" : "No match"}
          </div>
        )}
        {displayed.map((entry) => (
          <div
            key={entry.id}
            className="px-2 py-1.5 space-y-1 border-b border-border/20"
          >
            <div className="text-[10px] font-medium truncate">{entry.title}</div>

            {/* Username row */}
            {entry.hasUsername && (
              <div className="flex items-center gap-1">
                <span className="text-[9px] text-muted-foreground w-5 shrink-0">
                  usr
                </span>
                <span className="text-[9px] flex-1 truncate">
                  {revealField === `${entry.id}-usr`
                    ? entry.username
                    : "••••••"}
                </span>
                <Button
                  variant="ghost"
                  size="icon-xs"
                  className="size-4"
                  onClick={() =>
                    setRevealField(
                      revealField === `${entry.id}-usr`
                        ? null
                        : `${entry.id}-usr`
                    )
                  }
                >
                  {revealField === `${entry.id}-usr` ? (
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
                    navigator.clipboard.writeText(entry.username)
                  }
                >
                  <Copy className="size-2" />
                </Button>
              </div>
            )}

            {/* Password row */}
            <div className="flex items-center gap-1">
              <span className="text-[9px] text-muted-foreground w-5 shrink-0 flex items-center gap-0.5">
                psk
                {entry.useDefaultPin && !isUnlocked() && (
                  <Lock className="size-2" />
                )}
              </span>
              <span className="text-[9px] flex-1 truncate">
                {revealField === `${entry.id}-psk`
                  ? entry.password
                  : "••••••"}
              </span>
              <Button
                variant="ghost"
                size="icon-xs"
                className="size-4"
                onClick={() =>
                  requestPasswordAction(entry, {
                    kind: "reveal",
                    entryId: entry.id,
                  })
                }
              >
                {revealField === `${entry.id}-psk` ? (
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
                  requestPasswordAction(entry, {
                    kind: "copy",
                    value: entry.password,
                  })
                }
              >
                <Copy className="size-2" />
              </Button>
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
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
              setCurrentIndex((i) =>
                (i - 1 + filtered.length) % filtered.length
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
              requestPasswordAction(currentEntry, {
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

  // ─── ADD VIEW ───
  const addView = (
    <div className="px-1 pb-1 space-y-2 flex-1">
      <Input
        placeholder="Title"
        value={newTitle}
        onChange={(e) => setNewTitle(e.target.value)}
        className="h-6 text-[10px] px-2 rounded-sm"
      />

      {/* Username group */}
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

      {/* Password group */}
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

      {/* Default PIN group (no text input, just a toggle row) */}
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
        disabled={!newTitle.trim()}
      >
        <Check className="size-3 mr-1" />
        <span className="text-[10px]">Save</span>
      </Button>
    </div>
  );

  // ─── SETTINGS VIEW ───
  const settingsView = (
    <div className="flex flex-col items-center justify-center px-2.5 py-4 gap-2">
      <span className="text-[10px] text-muted-foreground">
        Global Unlock PIN
      </span>
      <InputOTP
        maxLength={4}
        value={globalPin}
        onChange={setGlobalPin}
        inputMode="numeric"
        pattern="[0-9]*"
        containerClassName="gap-1"
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
    </div>
  );

  // ─── SET-PIN VIEW (per-item) ───
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
        maxLength={4}
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
        onClick={() => commitEntry(newCustomPin)}
        disabled={newCustomPin.length !== 4}
      >
        <Check className="size-3 mr-1" />
        <span className="text-[10px]">Save</span>
      </Button>
    </div>
  );

  // ─── UNLOCK OVERLAY ───
  const unlockOverlay = pendingAction && (
    <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 bg-background/95 backdrop-blur-sm">
      <span className="text-[9px] text-muted-foreground uppercase tracking-wider">
        Enter PIN
      </span>
      <InputOTP
        maxLength={4}
        value={pinInput}
        onChange={setPinInput}
        inputMode="numeric"
        pattern="[0-9]*"
        containerClassName="gap-1"
        autoFocus
      >
        <InputOTPGroup>
          <MaskedOTPSlot index={0} status={pinStatus} />
          <MaskedOTPSlot index={1} status={pinStatus} />
        </InputOTPGroup>
        <InputOTPSeparator />
        <InputOTPGroup>
          <MaskedOTPSlot index={2} status={pinStatus} />
          <MaskedOTPSlot index={3} status={pinStatus} />
        </InputOTPGroup>
      </InputOTP>
      <button
        onClick={cancelUnlock}
        className="text-[9px] text-muted-foreground hover:text-foreground"
      >
        cancel
      </button>
    </div>
  );

  // Dynamic window sizing: match content with smooth transition
  const rootRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;

    const DURATION = 180; // ms
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
      if (t < 1) {
        rafId = requestAnimationFrame(tick);
      } else {
        rafId = 0;
      }
    };

    const ro = new ResizeObserver((entries) => {
      const rect = entries[0]?.contentRect;
      if (!rect) return;
      const w = Math.ceil(rect.width);
      const h = Math.ceil(rect.height);
      if (w <= 0 || h <= 0) return;

      if (!initialized) {
        // First measurement — snap without animating
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

  return (
    <div
      ref={rootRef}
      className="relative w-[145px] overflow-hidden rounded-md border border-border/30 bg-background shadow-2xl flex flex-col"
      data-tauri-drag-region
    >
      {titleBar}
      {view === "list" && listView}
      {view === "add" && addView}
      {view === "settings" && settingsView}
      {view === "set-pin" && setPinView}
      {unlockOverlay}
    </div>
  );
}

export default App;
