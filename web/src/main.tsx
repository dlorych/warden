import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

type User = { subject: string; name: string }
type Session = { authenticated: boolean; user?: User; csrfToken?: string }
type RequestItem = {
  id: string; repository: string; environment: string; commit_sha: string; requester: string
  created_at: string; expires_at: string; decision: string; log_status: string; delivery_status: string; reason?: string
}
type Evidence = { id?: string; kind?: string; digest?: string; payload?: unknown; [key: string]: unknown }

const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(path, { credentials: 'same-origin', ...init, headers: { Accept: 'application/json', ...(init?.headers || {}) } })
  if (!response.ok) throw new Error((await response.text()).slice(0, 240) || `${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}
const ago = (value: string) => { const d = Date.now() - new Date(value).getTime(); const m = Math.round(d / 60000); return m < 1 ? 'just now' : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago` }
const shortSha = (s: string) => s ? `${s.slice(0, 7)}` : '—'
const statusClass = (s: string) => `status status-${s.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`

function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { api<Session>('/bff/session').then(setSession).catch(e => setError(e.message)) }, [])
  if (error) return <Shell><ErrorBox message={error} /></Shell>
  if (!session) return <Shell><Spinner label="Checking your session…" /></Shell>
  if (!session.authenticated) return <Shell><div className="login-card"><div className="mark">W</div><h1>Deploy with confidence.</h1><p>Warden gives every production deployment a clear, auditable approval trail.</p><button onClick={() => { window.location.href = '/bff/login' }}>Sign in with SSO <span>↗</span></button></div></Shell>
  return <Authenticated session={session} />
}

function Authenticated({ session }: { session: Session }) {
  const [selected, setSelected] = useState<string | null>(() => location.pathname.match(/\/requests\/([^/]+)/)?.[1] || null)
  const [items, setItems] = useState<RequestItem[]>([])
  const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [nextCursor, setNextCursor] = useState('')
  const load = useCallback(async (cursor = '') => { setLoading(true); try { const x = await api<{ items?: RequestItem[]; nextCursor?: string; next_cursor?: string }>(`/bff/requests${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`); setItems(cursor ? [...items, ...(x.items || [])] : (x.items || [])); setNextCursor(x.nextCursor || x.next_cursor || ''); setError('') } catch (e) { setError((e as Error).message) } finally { setLoading(false) } }, [items])
  useEffect(() => { void load() }, [])
  useEffect(() => { const timer = window.setInterval(() => { if (!document.hidden) void load() }, 15000); return () => clearInterval(timer) }, [load])
  const open = (id: string) => { setSelected(id); history.pushState({}, '', `/requests/${id}`) }
  useEffect(() => { const f = () => setSelected(location.pathname.match(/\/requests\/([^/]+)/)?.[1] || null); addEventListener('popstate', f); return () => removeEventListener('popstate', f) }, [])
  return <Shell user={session.user} csrf={session.csrfToken}><div className="layout"><aside className="sidebar"><div className="brand"><span className="brand-mark">W</span><span>warden</span></div><div className="side-label">Workspace</div><nav><button className="nav-active"><span>◈</span> Requests <b>{items.filter(x => x.decision === 'pending').length || ''}</b></button><button onClick={() => alert('Audit history is available per request.')}><span>◷</span> Audit log</button></nav><div className="side-foot"><span className="online" /> Local development</div></aside><main className="main"><header className="topbar"><div><div className="eyebrow">Operations / approvals</div><h2>Deployment requests</h2></div><div className="top-actions"><button className="icon-btn" title="Refresh" onClick={() => void load()}>↻</button><div className="avatar">{(session.user?.name || 'U').slice(0, 1).toUpperCase()}</div><span className="username">{session.user?.name || 'Signed in'}</span><button className="logout" onClick={() => void logout(session.csrfToken)}>Log out</button></div></header><div className="content">{selected ? <RequestDetail id={selected} csrf={session.csrfToken} onBack={() => { open(''); history.pushState({}, '', '/'); }} /> : <RequestList items={items} loading={loading} error={error} nextCursor={nextCursor} onOpen={open} onMore={() => void load(nextCursor)} onRetry={() => void load()} />}</div></main></div></Shell>
}
async function logout(csrf?: string) {
  let redirected = false
  try {
    const result = await api<{ logoutURL?: string }>('/bff/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf || '' } })
    if (result.logoutURL) { redirected = true; window.location.assign(result.logoutURL); return }
  } finally { if (!redirected && !document.hidden) location.reload() }
}

function RequestList({ items, loading, error, nextCursor, onOpen, onMore, onRetry }: { items: RequestItem[]; loading: boolean; error: string; nextCursor: string; onOpen: (id: string) => void; onMore: () => void; onRetry: () => void }) {
  return <><div className="toolbar"><div><p className="lede">Review deployment changes before they reach protected environments.</p></div><button className="refresh" onClick={onRetry}>Refresh <span>↻</span></button></div>{error && <ErrorBox message={error} retry={onRetry} />}{loading && !items.length ? <Spinner label="Loading requests…" /> : items.length === 0 ? <div className="empty"><div className="empty-icon">✓</div><h3>Nothing needs your attention</h3><p>New deployment requests will appear here when a protected environment is waiting for a decision.</p></div> : <div className="table-wrap"><table><thead><tr><th>Request</th><th>Environment</th><th>Commit</th><th>Requester</th><th>Created</th><th>Decision</th><th></th></tr></thead><tbody>{items.map(item => <tr key={item.id} onClick={() => onOpen(item.id)}><td><strong>{item.repository}</strong><small className="mono">#{item.id.slice(0, 8)}</small></td><td><span className="env-dot" />{item.environment}</td><td className="mono">{shortSha(item.commit_sha)}</td><td>{item.requester}</td><td className="muted">{ago(item.created_at)}</td><td><span className={statusClass(item.decision)}>{item.decision || 'pending'}</span></td><td className="chevron">›</td></tr>)}</tbody></table>{nextCursor && <button className="load-more" onClick={onMore}>Load more</button>}</div>}</>
}

function RequestDetail({ id, csrf, onBack }: { id: string; csrf?: string; onBack: () => void }) {
  const [item, setItem] = useState<RequestItem | null>(null); const [evidence, setEvidence] = useState<Evidence[]>([]); const [loading, setLoading] = useState(true); const [error, setError] = useState('')
  const load = useCallback(async () => { setLoading(true); try { const [r, e] = await Promise.all([api<RequestItem>(`/bff/requests/${encodeURIComponent(id)}`), api<{ items?: Evidence[] }>(`/bff/requests/${encodeURIComponent(id)}/evidence`)]); setItem(r); setEvidence(e.items || []); setError('') } catch (x) { setError((x as Error).message) } finally { setLoading(false) } }, [id])
  useEffect(() => { void load(); const t = window.setInterval(() => { if (!document.hidden) void load() }, 10000); return () => clearInterval(t) }, [load])
  if (loading && !item) return <><button className="back" onClick={onBack}>← Requests</button><Spinner label="Loading request…" /></>
  if (error && !item) return <><button className="back" onClick={onBack}>← Requests</button><ErrorBox message={error} retry={() => void load()} /></>
  if (!item) return null
  const pending = item.decision === 'pending' || !item.decision
  return <div className="detail"><button className="back" onClick={onBack}>← All requests</button><div className="detail-head"><div><div className="eyebrow">Deployment request</div><h2>{item.repository} <span className="slash">/</span> {item.environment}</h2><p className="muted">Submitted by {item.requester} · {ago(item.created_at)} · expires {new Date(item.expires_at).toLocaleString()}</p></div><span className={statusClass(item.decision)}>{item.decision || 'pending'}</span></div>{error && <ErrorBox message={error} />}{item.reason && <div className="reason"><span>Reason</span>{item.reason}</div>}<div className="detail-grid"><section className="panel"><div className="panel-title">Change details</div><div className="facts"><div><small>Repository</small><b>{item.repository}</b></div><div><small>Environment</small><b>{item.environment}</b></div><div><small>Commit SHA</small><b className="mono">{item.commit_sha}</b></div><div><small>Delivery</small><b className={statusClass(item.delivery_status)}>{item.delivery_status || 'pending'}</b></div><div><small>Transparency log</small><b className={statusClass(item.log_status)}>{item.log_status || 'pending'}</b></div></div></section><section className="panel"><div className="panel-title">Evidence <span>{evidence.length}</span></div>{evidence.length ? <div className="evidence-list">{evidence.map((x, i) => <details key={x.id || i}><summary><span className="evidence-dot" />{x.kind || 'Signed evidence'}<code>{x.digest ? String(x.digest).slice(0, 16) : 'available'}</code></summary><pre>{JSON.stringify(x.payload || x, null, 2)}</pre></details>)}</div> : <p className="panel-empty">Evidence is being collected for this request.</p>}</section></div><div className="decision-bar">{pending ? <><div><strong>Ready for your decision?</strong><p>Use the CLI to authenticate, show this bound request, collect a reason, and sign the decision.</p></div><div className="decision-actions"><button className="approve" onClick={() => void navigator.clipboard?.writeText(`warden decide ${item.id}`)}>Copy CLI command</button></div></> : <div><strong>Decision recorded: {item.decision}</strong><p>The request will continue through its delivery workflow.</p></div>}</div><button className="cli-copy" onClick={() => void navigator.clipboard?.writeText(`warden decide ${item.id}`)}>Copy CLI command <span>⧉</span></button></div>
}

function Shell({ children, user, csrf }: { children: React.ReactNode; user?: User; csrf?: string }) { return <div className="shell">{children}</div> }
function Spinner({ label }: { label: string }) { return <div className="spinner"><i />{label}</div> }
function ErrorBox({ message, retry }: { message: string; retry?: () => void }) { return <div className="error"><strong>Something went wrong</strong><span>{message}</span>{retry && <button onClick={retry}>Try again</button>}</div> }
createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
