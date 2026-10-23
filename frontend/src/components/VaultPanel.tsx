import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorNote } from "./Shared";

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

  async function load(t: string) {
    try { setItems(await api.vaultList(t)); } catch { setItems([]); }
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
    try {
      await api.vaultCreate(token, title, secret, master);
      setTitle(""); setSecret("");
      await load(token);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not save item"); }
  }

  async function open(id: number) {
    setError("");
    try {
      const r = await api.vaultOpen(token, id, master);
      setOpened(r.secret);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not open item"); }
  }

  if (!token) {
    return (
      <section className="card">
        <div className="card-head"><h2>🗄️ Encrypted Vault</h2><span className="tag">Module 06</span></div>
        <p className="hint">Store recovery codes, PINs and notes encrypted with AES-256-GCM. The server only ever sees ciphertext. Passwords need 12+ characters.</p>
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
        <input type="password" value={master} onChange={(e) => setMaster(e.target.value)} placeholder="Master password (encrypts/decrypts items)" required aria-label="Master password" />
        <button>Add encrypted item</button>
      </form>
      <ErrorNote error={error} />
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
