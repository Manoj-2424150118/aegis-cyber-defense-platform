import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorNote, PasswordInput, Spinner } from "./Shared";
import { LockIcon } from "./icons";

/* Session model: the access token lives only in page memory and the
 * refresh token in an HttpOnly cookie — nothing auth-related sits in
 * web storage where injected script could read it. When the access
 * token expires (30 min) or the account is gone, a call returns a
 * session 401: try one silent cookie refresh and retry; if that fails,
 * end the session gracefully with an explanation. */
const SESSION_ERRORS = ["Account no longer exists.", "Invalid or expired token.", "Authentication required.", "Invalid refresh token."];
const SESSION_NOTICE =
  "Your session ended. Please log in again to open your vault.";

function isSessionError(err: unknown): boolean {
  return err instanceof Error && SESSION_ERRORS.some((s) => err.message.includes(s));
}

export function VaultPanel() {
  const [token, setToken] = useState<string>("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [items, setItems] = useState<{ id: number; title: string }[]>([]);
  const [title, setTitle] = useState("");
  const [secret, setSecret] = useState("");
  const [master, setMaster] = useState("");
  const [opened, setOpened] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [account, setAccount] = useState<{ plan: string; totp_enabled: boolean } | null>(null);
  const [mfaPending, setMfaPending] = useState("");
  const [mfaMgmtPw, setMfaMgmtPw] = useState("");
  const [mfaMgmtCode, setMfaMgmtCode] = useState("");
  const [mfaMsg, setMfaMsg] = useState("");

  function endSession(notice = true) {
    setMode("login");
    setToken("");
    setItems([]);
    setOpened("");
    if (notice) setError(SESSION_NOTICE);
  }

  async function refreshSession(): Promise<string | null> {
    try {
      const r = await api.refresh();
      setToken(r.access_token);
      return r.access_token;
    } catch {
      return null;
    }
  }

  // On first mount, restore the session from the refresh cookie (this
  // is what keeps a user logged in across page reloads).
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const r = await api.refresh();
        if (!cancelled) setToken(r.access_token);
      } catch (err) {
        if (!cancelled && err instanceof Error && err.message.includes("Account no longer exists.")) {
          setError("That account no longer exists. Please create it again.");
        }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  async function load(t: string) {
    try { setItems(await api.vaultList(t)); }
    catch (err) {
      if (isSessionError(err)) {
        const fresh = await refreshSession();
        if (fresh) { try { setItems(await api.vaultList(fresh)); return; } catch { /* fall through */ } }
        endSession();
      } else setItems([]);
    }
  }
  useEffect(() => { if (token) void load(token); }, [token]);

  async function auth(e: React.FormEvent) {
    e.preventDefault(); setError("");
    setBusy(true);
    try {
      const r = mode === "login" ? await api.login(email, password) : await api.register(email, password);
      if (r.mfa_required && r.challenge) { setMfaChallenge(r.challenge); setMfaCode(""); return; }
      setToken(r.access_token);
    } catch (err) { setError(err instanceof Error ? err.message : "Authentication failed"); }
    finally { setBusy(false); }
  }

  async function submitMfa(e: React.FormEvent) {
    e.preventDefault(); setError("");
    setBusy(true);
    try {
      const r = await api.loginMfa(mfaChallenge, mfaCode);
      setMfaChallenge("");
      setToken(r.access_token);
    } catch (err) { setError(err instanceof Error ? err.message : "Invalid code"); }
    finally { setBusy(false); }
  }

  useEffect(() => {
    if (!token) { setAccount(null); return; }
    let cancelled = false;
    void (async () => {
      try { const me = await api.me(token); if (!cancelled) setAccount({ plan: me.plan, totp_enabled: me.totp_enabled }); }
      catch { /* account extras are best-effort */ }
    })();
    return () => { cancelled = true; };
  }, [token]);

  async function mfaSetupStart() {
    setMfaMsg(""); setError("");
    try {
      const r = await api.mfaSetup(token, mfaMgmtPw);
      setMfaPending(r.secret);
      setMfaMsg("Add this secret to your authenticator app (or scan via the otpauth link in your app), then enter a code to confirm.");
    } catch (err) { setError(err instanceof Error ? err.message : "Setup failed"); }
  }

  async function mfaConfirm() {
    setMfaMsg(""); setError("");
    try {
      await api.mfaConfirm(token, mfaMgmtCode);
      setMfaPending(""); setMfaMgmtCode(""); setMfaMgmtPw("");
      setAccount((a) => (a ? { ...a, totp_enabled: true } : a));
      setMfaMsg("Two-factor authentication is on. You will be asked for a code at each login.");
    } catch (err) { setError(err instanceof Error ? err.message : "Confirmation failed"); }
  }

  async function mfaDisable() {
    setMfaMsg(""); setError("");
    try {
      await api.mfaDisable(token, mfaMgmtPw, mfaMgmtCode);
      setMfaMgmtCode(""); setMfaMgmtPw("");
      setAccount((a) => (a ? { ...a, totp_enabled: false } : a));
      setMfaMsg("Two-factor authentication is off.");
    } catch (err) { setError(err instanceof Error ? err.message : "Could not disable"); }
  }

  async function add(e: React.FormEvent) {
    e.preventDefault(); setError("");
    if (master.length < 12) { setError("Master password needs at least 12 characters."); return; }
    setBusy(true);
    try {
      await api.vaultCreate(token, title, secret, master);
      setTitle(""); setSecret("");
      await load(token);
    } catch (err) {
      if (isSessionError(err)) {
        const fresh = await refreshSession();
        if (fresh) { await load(fresh); return; }
        endSession();
      } else setError(err instanceof Error ? err.message : "Could not save item");
    } finally { setBusy(false); }
  }

  async function open(id: number) {
    setError("");
    setOpened(""); // never leave a stale decrypted secret on screen beside a new error
    try {
      const r = await api.vaultOpen(token, id, master);
      setOpened(r.secret);
    } catch (err) {
      if (isSessionError(err)) {
        const fresh = await refreshSession();
        if (fresh) {
          try { const r = await api.vaultOpen(fresh, id, master); setOpened(r.secret); return; }
          catch { /* fall through */ }
        }
        endSession();
      } else setError(err instanceof Error ? err.message : "Could not open item");
    }
  }

  async function logout() {
    await api.logout();
    endSession(false);
    setError("");
  }

  if (!token) {
    return (
      <section className="card" id="tool-vault">
        <div className="card-head">
          <span className="tile"><LockIcon size={20} /></span>
          <h2>Encrypted Vault</h2>
          <span className="tag">Vault</span>
        </div>
        <p className="hint">Recovery codes, PINs and notes, encrypted with AES-256-GCM. The server only ever sees ciphertext.</p>
        {mfaChallenge ? (
        <form onSubmit={submitMfa} className="stack">
          <div className="field">
            <span id="v-mfa-label">Authenticator code</span>
            <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" autoComplete="one-time-code" required aria-labelledby="v-mfa-label" />
          </div>
          <button disabled={busy}>{busy ? <><Spinner /> Verifying…</> : "Verify and log in"}</button>
          <button type="button" className="linklike" onClick={() => setMfaChallenge("")}>Back to login</button>
        </form>
        ) : (
        <form onSubmit={auth} className="stack">
          <div className="field">
            <span id="v-email-label">Email</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" required aria-labelledby="v-email-label" autoComplete="email" />
          </div>
          <div className="field">
            <span id="v-pass-label">Account password</span>
            <PasswordInput value={password} onChange={setPassword} placeholder="12+ characters" ariaLabel="Account password" autoComplete={mode === "login" ? "current-password" : "new-password"} required />
          </div>
          <button disabled={busy}>{busy ? <><Spinner /> Working…</> : mode === "login" ? "Log in" : "Create account"}</button>
          <button type="button" className="linklike" onClick={() => setMode(mode === "login" ? "register" : "login")}>
            {mode === "login" ? "New here? Create an account" : "Already registered? Log in"}
          </button>
        </form>
        )}
        <ErrorNote error={error} />
      </section>
    );
  }

  return (
    <section className="card" id="tool-vault">
      <div className="card-head">
        <span className="tile"><LockIcon size={20} /></span>
        <h2>Encrypted Vault</h2>
        <span className="tag">Vault</span>
      </div>
      <p className="hint">Your master password encrypts and decrypts items on this device. It is never sent to or stored by the server — if you forget it, items cannot be recovered.</p>
      <form onSubmit={add} className="stack">
        <div className="field">
          <span id="v-title-label">Title</span>
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Bank recovery codes" required aria-labelledby="v-title-label" />
        </div>
        <div className="field">
          <span id="v-secret-label">Secret to encrypt</span>
          <input value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="The code, PIN or note itself" required aria-labelledby="v-secret-label" />
        </div>
        <div className="field">
          <span id="v-master-label">Master password</span>
          <PasswordInput value={master} onChange={setMaster} placeholder="12+ characters" ariaLabel="Master password" required />
        </div>
        <button disabled={busy}>{busy ? <><Spinner /> Encrypting…</> : "Add encrypted item"}</button>
      </form>
      <ErrorNote error={error} />
      <p className="meta">Demo note: don't keep real secrets here.</p>
      <ul className="vault-list">
        {items.map((i) => (
          <li key={i.id}><span>{i.title}</span><button className="secondary" onClick={() => open(i.id)}>Open</button></li>
        ))}
      </ul>
      {opened && <p className="generated">Decrypted: <code>{opened}</code></p>}
      <div className="account-box">
        <h3>Account security</h3>
        <p className="meta">
          Plan: {account?.plan === "pro" ? "Pro" : "Free account"}
          {account?.plan !== "pro" && <> · Vault {items.length}/20 items</>}
          {" "}· Two-factor: {account?.totp_enabled ? "on" : "off"}
        </p>
        {!account?.totp_enabled && !mfaPending && (
          <div className="stack">
            <div className="field">
              <span id="v-mfapw-label">Account password</span>
              <PasswordInput value={mfaMgmtPw} onChange={setMfaMgmtPw} placeholder="Confirm it's you" ariaLabel="Account password" />
            </div>
            <button type="button" className="secondary" onClick={() => void mfaSetupStart()}>Set up two-factor (TOTP)</button>
          </div>
        )}
        {mfaPending && (
          <div className="stack">
            <p className="meta">Secret: <code>{mfaPending}</code></p>
            <div className="field">
              <span id="v-mfacode-label">Code from your app</span>
              <input value={mfaMgmtCode} onChange={(e) => setMfaMgmtCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" aria-labelledby="v-mfacode-label" />
            </div>
            <button type="button" onClick={() => void mfaConfirm()}>Confirm and enable</button>
          </div>
        )}
        {account?.totp_enabled && (
          <div className="stack">
            <div className="field">
              <span id="v-mfapw2-label">Account password</span>
              <PasswordInput value={mfaMgmtPw} onChange={setMfaMgmtPw} placeholder="Confirm it's you" ariaLabel="Account password" />
            </div>
            <div className="field">
              <span id="v-mfacode2-label">Current code</span>
              <input value={mfaMgmtCode} onChange={(e) => setMfaMgmtCode(e.target.value)} placeholder="6-digit code" inputMode="numeric" aria-labelledby="v-mfacode2-label" />
            </div>
            <button type="button" className="secondary" onClick={() => void mfaDisable()}>Turn off two-factor</button>
          </div>
        )}
        {mfaMsg && <p className="meta">{mfaMsg}</p>}
      </div>
      <button className="linklike" onClick={() => void logout()}>Log out</button>
    </section>
  );
}
