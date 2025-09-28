import React from 'react'
import { createRoot } from 'react-dom/client'

function App() {
  const [email, setEmail] = React.useState('demo@aurora.dev')
  const [password, setPassword] = React.useState('123456')
  const [token, setToken] = React.useState(localStorage.getItem('token') || '')
  const [msg, setMsg] = React.useState('')

  async function call(path, body) {
    const r = await fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body)
    })
    return r.json()
  }

  async function register() {
    setMsg('registrando...')
    const res = await call('/auth/register', { email, password })
    if (res.ok) { localStorage.setItem('token', res.token); setToken(res.token); setMsg('registrado') } else setMsg(res.msg || 'erro')
  }
  async function login() {
    setMsg('logando...')
    const res = await call('/auth/login', { email, password })
    if (res.ok) { localStorage.setItem('token', res.token); setToken(res.token); setMsg('login ok') } else setMsg(res.msg || 'erro')
  }
  function logout() { localStorage.removeItem('token'); setToken(''); setMsg('logout') }

  async function createEvent() {
    setMsg('criando evento...')
    const res = await call('/events', { title:'Aurora Conf', date:'2030-01-01T10:00:00.000Z', location:'Online' })
    setMsg(res.ok ? 'evento criado' : (res.msg || 'erro'))
  }
  async function listEvents() {
    const r = await fetch('/api/events'); const j = await r.json()
    setMsg(j.ok ? `eventos: ${j.events.length}` : 'erro')
  }

  return (
    <div style={{ fontFamily:'system-ui', padding:24, maxWidth:640 }}>
      <h1>Aurora — Front</h1>
      <p>Proxy via <code>/api/*</code> (Nginx).</p>
      <div style={{display:'grid', gap:8}}>
        <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="email" />
        <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="senha" type="password" />
        <div style={{display:'flex', gap:8}}>
          <button onClick={register}>Registrar</button>
          <button onClick={login}>Login</button>
          <button onClick={logout} disabled={!token}>Logout</button>
        </div>
        <div style={{display:'flex', gap:8, marginTop:8}}>
          <button onClick={createEvent} disabled={!token}>Criar evento</button>
          <button onClick={listEvents}>Listar eventos</button>
        </div>
        <div>status: {msg}</div>
        <textarea readOnly value={token} style={{width:'100%',height:120,marginTop:8}}/>
      </div>
    </div>
  )
}
createRoot(document.getElementById('root')).render(<App />)
