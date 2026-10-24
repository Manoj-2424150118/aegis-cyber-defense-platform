import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorNote } from "./Shared";

/* The demo runs on free hosting with temporary storage: every
 * redeploy resets the account database, while the browser keeps its
 * login token — so a returning user can hold a token for an account
 * that no longer exists. Detect those 401s and end the session
 * gracefully with an explanation instead of a cryptic API error. */
const SESSION_ERRORS = ["Account no longer exists.", "Invalid or expired token.", "Authentication required.", "Invalid refresh token."];
const SESSION_NOTICE =
  "Your session ended — the free demo's storage resets whenever the app is redeployed, so demo accounts and vault items don't persist. Please create the account again, and never store real secrets in the demo.";

function isSessionError(err: unknown): boolean {
  return err instanceof Error && SESSION_ERRORS.some((s) => err.message.includes(s));
}

export function VaultPanel() {
  const [token, setToken] = useState<string>(() => localStorage.getItem("aegis_token") ?? "");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [items, setItems] = useState<{ id: number; title: string }[]>([]);
  const [title, setTitle] = useState("");
  const [secret, setSecret] = useState("");
  const [master, setMaster] = useState("");
  const [opened, setOpened] = useState("");
  const [error, setError] = useState("");

  function endSession() {
    localStorage.removeItem("aegis_token");
    setToken("");
    setItems([]);
    setOpened("");
    setError(SESSION_NOTICE);
  }

  async function load(t: string) {
    try { setItems(await api.vaultList(t)); }
    catch (err) { if (isSessionError(err)) endSession(); else setItems([]); }
  }
  useEffect(() => { if (token) void load(token); }, [token]);

  async function auth(e: React.FormEvent) {
    e.preventDefault(); setError("");
    try {
      const r = mode === "login" ? await api.login(email, password) : await api.register(email, password);
      localStorage.setItem("aegis_token", r.access_token);
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
    } catch (err) { if (isSessionError(err)) endSession(); else setError(err instanceof Error ? err.message : "Could not save item"); }
  }

  async function open(id: number) {
    setError("");
    try {
      const r = await api.vaultOpen(token, id, master);
      setOpened(r.secret);
    } catch (err) { if (isSessionError(err)) endSession(); else setError(err instanceof Error ? err.message : "Could not open item"); }
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
      <p className="meta">Demo note: storage resets on redeploys — don't keep real secrets here.</p>
      <ul className="vault-list">
        {items.map((i) => (
          <li key={i.id}><span>{i.title}</span><button className="secondary" onClick={() => open(i.id)}>Open</button></li>
        ))}
      </ul>
      {opened && <p className="generated">Decrypted: <code>{opened}</code></p>}
      <button className="linklike" onClick={() => { localStorage.removeItem("aegis_token"); setToken(""); }}>Log out</button>
    </section>
  );
}
