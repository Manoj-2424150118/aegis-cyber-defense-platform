import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorNote } from "./Shared";

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

  function endSession(notice = true) {
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
    try {
      const r = mode === "login" ? await api.login(email, password) : await api.register(email, password);
      setToken(r.access_token);
    } catch (err) { setError(err instanceof Error ? err.message : "Authentication failed"); }
  }

  async function add(e: React.FormEvent) {
    e.preventDefault(); setError("");
    if (master.length < 12) { setError("Master password needs at least 12 characters."); return; }
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
    }
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
      <section className="card">
        <div className="card-head"><h2>🗄️ Encrypted Vault</h2><span className="tag">Module 06</span></div>
        <p className="hint">Recovery codes, PINs and notes, encrypted with AES-256-GCM — the server only ever sees ciphertext.</p>
        <form onSubmit={auth} className="stack">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" required aria-label="Email" />
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Account password (12+ characters)" required aria-label="Password" />
          <button>{mode === "login" ? "Log in" : "Create account"}</button>
          <button type="button" className="linklike" onClick={() => setMode(mode === "login" ? "register" : "login")}>
            {mode === "login" ? "New here? Create an account" : "Already registered? Log in"}
          </button>
        </form>
        <ErrorNote error={error} />
      </section>
    );
  }

  return (
    <section className="card">
      <div className="card-head"><h2>🗄️ Encrypted Vault</h2><span className="tag">Module 06</span></div>
      <form onSubmit={add} className="stack">
        <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title (e.g. Bank recovery codes)" required aria-label="Item title" />
        <input value={secret} onChange={(e) => setSecret(e.target.value)} placeholder="Secret to encrypt" required aria-label="Secret" />
        <input type="password" value={master} onChange={(e) => setMaster(e.target.value)} placeholder="Master password (12+ characters — encrypts/decrypts items)" required aria-label="Master password" />
        <button>Add encrypted item</button>
      </form>
      <ErrorNote error={error} />
      <p className="meta">Demo note: don't keep real secrets here.</p>
      <ul className="vault-list">
        {items.map((i) => (
          <li key={i.id}><span>{i.title}</span><button className="secondary" onClick={() => open(i.id)}>Open</button></li>
        ))}
      </ul>
      {opened && <p className="generated">Decrypted: <code>{opened}</code></p>}
      <button className="linklike" onClick={() => void logout()}>Log out</button>
    </section>
  );
}
