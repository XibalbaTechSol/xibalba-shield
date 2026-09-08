import { useEffect, useMemo, useState } from 'react'
import { Activity, ArrowRight, Bell, Check, CircleUserRound, Database, FileCheck2, Fingerprint, Gauge, Globe2, HardDrive, LockKeyhole, Menu, Radar, ServerCog, Shield, ShieldCheck, Terminal, TriangleAlert, X } from 'lucide-react'
import { ShieldApi } from './api'
import './App.css'

const fallbackDevices = [
  { id:'prod-api-01', name:'prod-api-01', os:'Ubuntu 24.04', status:'protected', policy:'v12.4', last_seen:'12s ago' },
  { id:'prod-worker-02', name:'prod-worker-02', os:'Ubuntu 22.04', status:'protected', policy:'v12.4', last_seen:'28s ago' },
  { id:'edge-gateway-04', name:'edge-gateway-04', os:'Ubuntu 22.04', status:'attention', policy:'v12.3', last_seen:'4m ago' },
]
const fallbackOutcomes = [
  { decision:'blocked', action:'process_exec', device_id:'prod-api-01', target:'/tmp/unknown-agent', time:'2 min ago' },
  { decision:'allowed', action:'tcp_connect', device_id:'prod-worker-02', target:'api.openai.com:443', time:'8 min ago' },
  { decision:'contained', action:'file_write', device_id:'edge-gateway-04', target:'/etc/systemd/system', time:'21 min ago' },
]

function Brand(){return <div className="brand"><img src="/shield-logo.png" alt="Xibalba Shield"/><b>Xibalba <i>Shield</i></b></div>}
function Landing({next}){return <main className="landing">
  <nav className="site-nav"><Brand/><div className="nav-links"><a href="#platform">Platform</a><a href="#proof">Trust</a><a href="#control">Control plane</a></div><div><button className="quiet" onClick={next}>Sign in</button><button className="primary" onClick={next}>Open console <ArrowRight/></button></div></nav>
  <section className="hero"><div className="hero-copy"><img src="/shield-logo.png" alt="Shield Logo" className="hero-logo" /><p className="eyebrow"><span/> LINUX-FIRST AGENT SECURITY</p><h1>Trust every action.<br/><em>Contain every threat.</em></h1><p className="lede">Observe, evaluate, and enforce policy at the edge—a verifiable security boundary built for autonomous agents.</p><div className="hero-actions"><button className="primary big" onClick={next}>Explore the console <ArrowRight/></button><a href="#platform">See how it works</a></div><div className="checks"><span><Check/>Kernel telemetry</span><span><Check/>Signed policies</span><span><Check/>Receipt-backed enforcement</span></div></div>
  <div className="hero-art"><div className="ring r1"/><div className="ring r2"/><div className="core"><Shield/><b>Policy verified</b></div><div className="signal s1"><Activity/><span>Process event<b>Allowed</b></span></div><div className="signal s2"><LockKeyhole/><span>Write attempt<b>Contained</b></span></div><div className="signal s3"><Globe2/><span>Network call<b>Verified</b></span></div></div></section>
  <section className="proof" id="proof"><div><b>Kernel-level</b><span>eBPF sensor coverage</span></div><div><b>Default deny</b><span>policy enforcement</span></div><div><b>Append-only</b><span>decision evidence</span></div><div><b>Local first</b><span>works without cloud</span></div></section>
  <section className="features" id="platform"><header><p className="eyebrow">THE SHIELD PLATFORM</p><h2>Security that moves at agent speed.</h2><p>One operational surface for fleet posture, policy decisions, and containment evidence.</p></header><div className="feature-grid">{[[Radar,'See every action','Process, file, and network telemetry in one live event stream.'],[Fingerprint,'Enforce identity','Bind decisions to verified agents, devices, and identities.'],[FileCheck2,'Prove the outcome','Every action produces durable, reviewable evidence.']].map(([Icon,title,copy])=><article key={title}><span><Icon/></span><h3>{title}</h3><p>{copy}</p><button onClick={next}>View in console <ArrowRight/></button></article>)}</div></section>
  <section className="cta"><div><p className="eyebrow">BUILT FOR REAL OPERATIONS</p><h2>Put your agent fleet behind a verifiable boundary.</h2></div><button onClick={next}>Open Shield <ArrowRight/></button></section>
  <footer><Brand/><span>Endpoint security for the agentic era.</span><small>© 2026 Xibalba</small></footer>
</main>}
const DEFAULT_CONTROL_PLANE = 'http://localhost:8765'

function SignIn({back,connect}){
  const [mode,setMode]=useState('login')
  const [advanced,setAdvanced]=useState(false)
  const [error,setError]=useState(()=>sessionStorage.getItem('shield-auth-notice')||'')
  const [busy,setBusy]=useState(false)

  useEffect(()=>{sessionStorage.removeItem('shield-auth-notice')},[])

  const submit=async event=>{
    event.preventDefault()
    const form=new FormData(event.currentTarget)
    const baseUrl=advanced?String(form.get('baseUrl')||DEFAULT_CONTROL_PLANE).trim():DEFAULT_CONTROL_PLANE
    setBusy(true)
    setError('')
    try{
      if(advanced){
        const tenant=String(form.get('tenant')||'').trim()
        const token=String(form.get('token')||'').trim()
        if(!tenant||!token)throw new Error('Tenant ID and admin token are required')
        const api=new ShieldApi(baseUrl,tenant,token)
        await api.dashboard()
        connect({tenant,token,baseUrl,account:null})
        return
      }

      const email=String(form.get('email')||'').trim()
      const password=String(form.get('password')||'')
      const payload=await new ShieldApi(baseUrl,'','').auth(mode,{
        email,
        password,
        display_name:String(form.get('displayName')||''),
        tenant_id:String(form.get('tenant')||'').trim(),
      })
      const tenant=payload.tenant_id
      const api=new ShieldApi(baseUrl,tenant,payload.admin_token)
      await api.dashboard()
      connect({
        tenant,
        token:payload.admin_token,
        baseUrl,
        account:{...payload.account,session_expires_at:payload.session_expires_at},
      })
    }catch(err){
      setError(err instanceof Error?err.message:String(err))
    }finally{
      setBusy(false)
    }
  }

  return <main className="auth">
    <button className="auth-back" onClick={back}>← Back to Shield</button>
    <section className="auth-story">
      <Brand/>
      <div><p className="eyebrow">SECURE OPERATOR ACCESS</p><h1>Your fleet.<br/>One trusted boundary.</h1><p>Sign in to view your protected devices, decisions, and evidence.</p></div>
      <aside><ShieldCheck/><span><b>Local-first authentication</b><small>Your credentials remain in this browser session.</small></span></aside>
    </section>
    <section className="auth-form">
      <form onSubmit={submit}>
        <span className="lock"><LockKeyhole/></span>
        {!advanced&&<div className="auth-tabs">
          <button type="button" className={mode==='login'?'active':''} onClick={()=>setMode('login')}>Sign in</button>
          <button type="button" className={mode==='signup'?'active':''} onClick={()=>setMode('signup')}>Create account</button>
        </div>}
        <h2>{advanced?'Advanced access':mode==='signup'?'Create your Shield account':'Welcome back'}</h2>
        <p>{advanced?'Connect with an administrator token and custom control plane.':mode==='signup'?'Create an operator account for your organization.':'Enter your email and password to continue.'}</p>
        {!advanced?<><label>Email<input name="email" type="email" autoFocus required/></label>{mode==='signup'&&<><label>Display name<input name="displayName" required/></label><label>Organization ID<input name="tenant" placeholder="acme-production" required/></label></>}<label>Password<input name="password" type="password" minLength="10" required/></label></>:<><label>Organization ID<input name="tenant" placeholder="acme-production" autoFocus required/></label><label>Admin token<input name="token" type="password" required/></label><label>Control plane URL<input name="baseUrl" defaultValue={DEFAULT_CONTROL_PLANE} required/></label></>}
        {error&&<div className="auth-error">{error}</div>}
        <button className="primary submit" disabled={busy}>{busy?'Connecting…':advanced?'Connect':mode==='signup'?'Create account':'Sign in'} <ArrowRight/></button>
        <button type="button" className="advanced" onClick={()=>{setAdvanced(value=>!value);setError('')}}>{advanced?'Back to email sign in':'Advanced access'}</button>
        <small className="session-note"><LockKeyhole/> Session-only credentials</small>
      </form>
    </section>
  </main>
}
function Metric({Icon,label,value,detail,tone}){return <article className="metric"><div><span className={tone||''}><Icon/></span>{label}</div><b>{value}</b><small>{detail}</small></article>}

const NAV = [
  ['overview', Gauge, 'Overview'], ['devices', HardDrive, 'Devices'], ['events', Activity, 'Event stream'],
  ['enforcement', LockKeyhole, 'Enforcement'], ['policies', FileCheck2, 'Policies'], ['evidence', Database, 'Evidence'],
  ['integrations', ServerCog, 'Integrations'], ['developer', Terminal, 'Developer'], ['settings', CircleUserRound, 'Settings'],
]

function Dashboard({ connection, logout }) {
  const [menu, setMenu] = useState(false)
  const [view, setView] = useState('overview')
  const [data, setData] = useState({ summary:null, devices:fallbackDevices, outcomes:fallbackOutcomes, exporter:[], integrations:[], quality:[], events:[] })
  const [status, setStatus] = useState({ state:'connecting', message:'Connecting to control plane' })
  const [refreshing, setRefreshing] = useState(false)
  const api = useMemo(() => new ShieldApi(connection.baseUrl, connection.tenant, connection.token), [connection])

  const refresh = async () => {
    setRefreshing(true)
    const results = await Promise.allSettled([api.dashboard(), api.devices(), api.enforcementOutcomes(), api.exporterStatus(), api.integrations(), api.detectionQuality(), api.testEvents()])
    const [summary, devices, outcomes, exporter, integrations, quality, events] = results
    const live = summary.status === 'fulfilled'
    setData(current => ({
      summary: live ? summary.value : current.summary,
      devices: devices.status === 'fulfilled' ? devices.value.devices : current.devices,
      outcomes: outcomes.status === 'fulfilled' ? outcomes.value.enforcement_outcomes : current.outcomes,
      exporter: exporter.status === 'fulfilled' ? exporter.value.exporter_status : current.exporter,
      integrations: integrations.status === 'fulfilled' ? integrations.value.integrations : current.integrations,
      quality: quality.status === 'fulfilled' ? quality.value.detection_quality : current.quality,
      events: events.status === 'fulfilled' ? events.value.test_events : current.events,
    }))
    const failure = summary.reason?.message || 'Authentication failed'
    if (!live && /401|unauthorized|invalid admin token|admin token required/i.test(failure)) { logout('Session expired. Sign in again to reconnect to this tenant.') ; return }
    setStatus(live ? { state:'live', message:'Control plane live' } : { state:'error', message:failure })
    setRefreshing(false)
  }
  useEffect(() => { refresh() }, [api])
  const protectedCount = data.summary?.device_count ?? data.devices.filter(d => d.status !== 'attention').length
  const openView = id => { setView(id); setMenu(false) }

  return <main className="console">
    <aside className={menu ? 'side open' : 'side'}><header><Brand/><button onClick={()=>setMenu(false)}><X/></button></header><nav><small>OPERATIONS</small>{NAV.slice(0,4).map(([id,Icon,label])=><button key={id} className={view===id?'active':''} onClick={()=>openView(id)}><Icon/>{label}{id==='devices'&&<i>{data.devices.length}</i>}</button>)}<small>CONTROL</small>{NAV.slice(4,6).map(([id,Icon,label])=><button key={id} className={view===id?'active':''} onClick={()=>openView(id)}><Icon/>{label}</button>)}<small>SYSTEM</small>{NAV.slice(6).map(([id,Icon,label])=><button key={id} className={view===id?'active':''} onClick={()=>openView(id)}><Icon/>{label}</button>)}</nav><div className="operator"><span>{(connection.account?.display_name || 'Shield Operator').split(/\s+/).map(x=>x[0]).join('').slice(0,2).toUpperCase()}</span><p><b>{connection.account?.display_name || 'Shield operator'}</b><small>{connection.account?.email || connection.tenant}</small></p><button title="Sign out" onClick={logout}>↗</button></div></aside>
    <section className="main"><header className="top"><button className="hamb" onClick={()=>setMenu(true)}><Menu/></button><div><h1>{NAV.find(x=>x[0]===view)?.[2]}</h1><p>{connection.tenant} · {connection.baseUrl}</p></div><div className="tools"><button title="Refresh" onClick={refresh} disabled={refreshing}><Activity/></button><button><Bell/></button><span className={`connection ${status.state}`} title={status.message}><i/>{status.state==='live'?'Control plane live':status.state==='connecting'?'Connecting':'Disconnected'}</span><CircleUserRound/></div></header>
      {status.state==='error'&&<div className="api-alert"><TriangleAlert/><span><b>Control plane unavailable</b>{status.message}. Showing clearly labeled preview data where available.</span><button onClick={refresh}>Retry</button></div>}
      <div className="content">{view==='overview' ? <Overview data={data} protectedCount={protectedCount} openView={openView} preview={status.state!=='live'}/> : <ResourceView view={view} data={data} api={api} refresh={refresh} connection={connection} logout={logout}/>}</div>
    </section>
  </main>
}

function Overview({ data, protectedCount, openView, preview = false }) {
  const actionCounts = data.summary?.decisions_by_action || {}
  const contained = (actionCounts.deny || 0) + (actionCounts.contain || 0)
  const latestStatus = data.exporter[0]?.status || data.summary?.exporter_status?.[0]?.status || {}
  const sensors = latestStatus.sensors || {}
  const exporter = latestStatus.exporter || {}
  return <><section className="welcome"><div><p className="eyebrow">OPERATIONAL POSTURE</p><h2>Fleet command center.</h2><span>Authenticated telemetry, policy decisions, and containment outcomes.</span></div><button className="primary" onClick={()=>openView('policies')}><ShieldCheck/>Deploy policy</button></section><section className="metrics"><Metric Icon={ShieldCheck} label="Enrolled devices" value={data.summary?.device_count ?? data.devices.length} detail="tenant-scoped" tone="green"/><Metric Icon={Activity} label="Latest event rate" value={data.summary?.latest_metrics?.events_per_sec ?? '—'} detail="events per second"/><Metric Icon={LockKeyhole} label="Contained / denied" value={contained} detail="recorded decisions" tone="green"/><Metric Icon={TriangleAlert} label="Exporter queue" value={exporter.spool_pending ?? exporter.queue_depth ?? '—'} detail="pending evidence" tone="amber"/></section><section className="panels"><article className="panel fleet"><PanelTitle title="Fleet health" copy="Authenticated device inventory"/><div className="fleet-body"><div className="donut"><span><b>{data.devices.length?Math.round(protectedCount/data.devices.length*100):0}%</b><small>visible</small></span></div><div className="legend"><p><i className="g"/>Enrolled <b>{data.devices.length}</b></p><p><i className="a"/>Lost events <b>{sensors.lost_events ?? '—'}</b></p><p><i/>Queue depth <b>{exporter.queue_depth ?? '—'}</b></p></div></div></article><article className="panel sensors"><PanelTitle title="Runtime health" copy="Latest watchdog publication" status={sensors.attached===true?'Operational':'Unverified'}/>{[['Policy',latestStatus.policy?.healthy,latestStatus.policy?.active_policy_hash],['OPA',latestStatus.opa?.healthy,'policy evaluator'],['Sensors',sensors.attached,`${sensors.lost_events ?? 0} lost events`],['Evidence exporter',exporter.export_failures===0,`${exporter.spool_pending ?? 0} spooled`]].map(([name,healthy,detail])=><div className="sensor" key={name}><span><Activity/></span><p><b>{name}</b><small>{detail || 'not reported'}</small></p><strong>{healthy===true?'healthy':healthy===false?'attention':'unknown'}</strong></div>)}</article></section><OutcomeTable outcomes={data.outcomes}/></>
}

function ResourceView({ view, data, api, refresh, connection, logout }) {
  if (view === 'devices') return <><Resource title="Devices" copy="Tenant-scoped enrolled endpoints"><div className="cards">{data.devices.map((d,i)=><article className="resource-card" key={d.device_id||d.id||i}><HardDrive/><div><h3>{d.device_id||d.name||'Unnamed device'}</h3><p>{d.device_role||d.os||'Endpoint'} · {d.enrolled_at||d.last_seen||'timestamp unavailable'}</p></div><span>{d.status||'enrolled'}</span></article>)}</div></Resource><ActionForm title="Enroll a device" copy="Issue a tenant-scoped device credential and configuration bundle." fields={[["deviceId","Device ID"],["deviceRole","Device role"]]} successText="Device enrolled successfully." submit={async values=>{await api.enrollDevice(values.deviceId, values.deviceRole || 'workstation');await refresh()}}/></>
  if (view === 'enforcement') return <OutcomeTable outcomes={data.outcomes}/>
  if (view === 'events') return <Resource title="Event stream" copy="Latest decisions and test events"><JsonRows rows={[...(data.summary?.latest_decisions||[]),...data.events]}/></Resource>
  if (view === 'evidence') return <><Resource title="Evidence & exporter" copy="DID preflight, sensor, queue, and receipt publication status"><JsonRows rows={data.exporter}/></Resource><RemediationForm api={api}/></>
  if (view === 'integrations') return <Resource title="Integrations" copy="Configured tenant export destinations"><JsonRows rows={data.integrations}/></Resource>
  if (view === 'settings') return <SettingsView connection={connection} logout={logout}/>
  if (view === 'developer') return <Resource title="Developer contract" copy="Connected authenticated API surface"><div className="developer-grid">{['dashboard-summary','devices','exporter-status','integrations','detection-quality','test-events','enforcement-outcomes'].map(x=><code key={x}>GET /api/shield/{x}</code>)}</div></Resource>
  if (view === 'policies') return <><ActionForm title="Deploy a signed policy bundle" copy="Writes require the connected tenant admin credential." fields={[['deviceId','Device ID'],['policyVersion','Policy version'],['policyHash','Policy hash']]} successText="Policy deployed successfully." submit={async values=>{if(!window.confirm('Deploy this policy to the selected device?')) return;await api.deployPolicy(values.deviceId,{version:values.policyVersion,policy_hash:values.policyHash,rules:[]});await refresh()}}/><RollbackForm api={api}/></>
  return <Resource title="Detection quality" copy="Measured adversarial detection and export quality"><JsonRows rows={data.quality}/></Resource>
}
function RollbackForm({api}) { const [message,setMessage]=useState(''); const submit=async event=>{event.preventDefault();const values=Object.fromEntries(new FormData(event.currentTarget));setMessage('Loading policy history…');try{const result=await api.policyHistory(values.deviceId);const latest=result.history?.[0];if(!latest) throw new Error('No previous policy is available for this device.');if(!window.confirm(`Rollback ${values.deviceId} to ${latest.policy_version}?`)) return;await api.rollbackPolicy(values.deviceId,latest.id);setMessage(`Rolled back to ${latest.policy_version}.`)}catch(error){setMessage(error.message)}};return <Resource title="Rollback a policy" copy="Restores the most recent prior policy version and records the replacement in history."><form className="action-form" onSubmit={submit}><label>Device ID<input name="deviceId" required/></label><button className="primary">Load and rollback latest</button>{message&&<p>{message}</p>}</form></Resource> }
function RemediationForm({api}) { const [message,setMessage]=useState(''); const submit=async event=>{event.preventDefault();const values=Object.fromEntries(new FormData(event.currentTarget));setMessage('Queueing remediation…');try{const result=await api.exporterRemediation(values.deviceId,values.action,values.reason);setMessage(`Request ${result.id} queued for the exporter worker.`)}catch(error){setMessage(error.message)}};return <Resource title="Exporter remediation" copy="Queue a retry, reconnect, or flush request for the authenticated tenant. Execution is explicitly worker-backed and auditable."><form className="action-form" onSubmit={submit}><label>Device ID<input name="deviceId" required/></label><label>Action<select name="action" defaultValue="retry"><option value="retry">Retry failed exports</option><option value="reconnect">Reconnect exporter</option><option value="flush">Flush pending queue</option></select></label><label>Reason<input name="reason" placeholder="Why is remediation needed?"/></label><button className="primary">Queue remediation</button>{message&&<p>{message}</p>}</form></Resource> }
function SettingsView({connection, logout}) {
  const account = connection.account || {}
  const [message, setMessage] = useState('')
  const [sessions, setSessions] = useState([])
  const api = useMemo(() => new ShieldApi(connection.baseUrl, connection.tenant, connection.token), [connection])
  useEffect(() => { if (account.id) api.sessions().then(result => setSessions(result.sessions || [])).catch(() => setSessions([])) }, [api, account.id])
  const changePassword = async event => { event.preventDefault(); const form = new FormData(event.currentTarget); setMessage('Updating…'); try { await api.changePassword(account.email || '', String(form.get('currentPassword') || ''), String(form.get('newPassword') || '')); event.currentTarget.reset(); setMessage('Password updated.'); } catch (error) { setMessage(error.message) } }
  return <Resource title="Account & control plane" copy="Server identity, tenant context, and this browser session"><div className="settings-grid"><article className="settings-card"><p className="eyebrow">ACCOUNT PROFILE</p><h3>{account.display_name || 'Shield operator'}</h3><dl><dt>Email</dt><dd>{account.email || 'Admin-token session'}</dd><dt>Role</dt><dd>{account.role || 'Tenant administrator'}</dd><dt>Account ID</dt><dd><code>{account.id || '—'}</code></dd><dt>Created</dt><dd>{account.created_at || '—'}</dd></dl>{account.email&&<form className="action-form" onSubmit={changePassword}><label>Current password<input name="currentPassword" type="password" required/></label><label>New password<input name="newPassword" type="password" minLength="10" required/></label><button className="primary">Change password</button>{message&&<p>{message}</p>}</form>}</article><article className="settings-card"><p className="eyebrow">TENANT SESSION</p><h3>{connection.tenant}</h3><dl><dt>Control plane</dt><dd><code>{connection.baseUrl}</code></dd><dt>Credential</dt><dd>{account.id ? 'Account-issued admin session' : 'Advanced admin token'}</dd><dt>Session expires</dt><dd>{account.session_expires_at || 'Until revoked'}</dd><dt>Last used</dt><dd>{sessions[0]?.last_used_at || 'Not recorded yet'}</dd><dt>Storage</dt><dd>Session-only browser storage</dd></dl><button className="danger-action" onClick={logout}>Sign out and revoke local session</button></article></div></Resource>
}
function TenantSwitcher(){const [connection]=useState(()=>{try{return JSON.parse(sessionStorage.getItem('shield-connection')||'{}')}catch{return {}}});const [message,setMessage]=useState('');const tenants=connection.account?.tenants||[];if(!connection.account?.email||tenants.length<2)return null;const switchTenant=async event=>{const target=event.target.value;if(!target||target===connection.tenant)return;setMessage('Switching…');try{const payload=await new ShieldApi(connection.baseUrl,connection.tenant,connection.token).switchTenant(connection.account.email,target);sessionStorage.setItem('shield-connection',JSON.stringify({baseUrl:connection.baseUrl,tenant:payload.tenant_id,token:payload.admin_token,account:{...payload.account,session_expires_at:payload.session_expires_at,tenants:payload.tenants||[]}}));window.location.reload()}catch(error){setMessage(error.message)}};return <div className="settings-card tenant-switcher"><p className="eyebrow">TENANT ACCESS</p><label>Active tenant<select value={connection.tenant} onChange={switchTenant}>{tenants.map(item=><option key={item.tenant_id} value={item.tenant_id}>{item.tenant_id} · {item.role}</option>)}</select></label>{message&&<p>{message}</p>}</div>}
function AvatarPreference(){const [avatar,setAvatar]=useState(()=>sessionStorage.getItem('shield-avatar')||'');const choose=event=>{const file=event.target.files?.[0];if(!file||!file.type.startsWith('image/'))return;if(file.size>2_000_000)return;const reader=new FileReader();reader.onload=()=>{const value=String(reader.result||'');sessionStorage.setItem('shield-avatar',value);setAvatar(value)};reader.readAsDataURL(file)};return <div className="settings-card avatar-preference"><p className="eyebrow">PROFILE PICTURE</p>{avatar&&<img src={avatar} alt="Operator profile" className="profile-avatar-image"/>}<label>Browser-local avatar<input type="file" accept="image/png,image/jpeg,image/gif,image/webp" onChange={choose}/></label>{avatar&&<button type="button" onClick={()=>{sessionStorage.removeItem('shield-avatar');setAvatar('')}}>Remove avatar</button>}</div>}
function AuditEvents({api,email}){const [events,setEvents]=useState([]);useEffect(()=>{api.authEvents(email).then(result=>setEvents(result.events||[])).catch(()=>setEvents([]))},[api,email]);return <div className="settings-card audit-events"><p className="eyebrow">SECURITY AUDIT</p><h3>Recent account events</h3>{events.length?events.slice(0,8).map((event,index)=><div className="audit-event" key={`${event.created_at}-${index}`}><b>{event.event_type}</b><small>{event.detail||''} · {event.created_at||''}</small></div>):<p>No audit events returned.</p>}</div>}
function Resource({title,copy,children}){const connection=title==='Account & control plane'?(()=>{try{return JSON.parse(sessionStorage.getItem('shield-connection')||'{}')}catch{return {}}})():{};const resourceApi=useMemo(()=>title==='Account & control plane'&&connection.baseUrl?new ShieldApi(connection.baseUrl,connection.tenant,connection.token):null,[title,connection.baseUrl,connection.tenant,connection.token]);return <section className="resource"><header><p className="eyebrow">LIVE CONTROL PLANE</p><h2>{title}</h2><span>{copy}</span><small className="evidence-label">Evidence class: authenticated local control-plane data; synthetic/demo records are labeled explicitly.</small></header>{title==='Account & control plane'&&<><TenantSwitcher/><AvatarPreference/>{resourceApi&&<AuditEvents api={resourceApi} email={connection.account?.email||''}/>}</>}{children}</section>}
function JsonRows({rows}){return <div className="json-rows">{rows.length?rows.map((row,i)=><details key={row.id||i}><summary>{row.integration_id||row.device_id||row.event_type||row.kind||`Record ${i+1}`}<span>{row.created_at||row.updated_at||''}</span></summary><pre>{JSON.stringify(row,null,2)}</pre></details>):<div className="empty"><Database/><h3>No records returned</h3><p>The authenticated endpoint returned an empty collection.</p></div>}</div>}
function OutcomeTable({outcomes}){const [selected,setSelected]=useState(null);return <><article className="panel events"><PanelTitle title="Enforcement outcomes" copy="Recorded containment attempts, including failures"/><div className="event-table"><header><span>RESULT</span><span>ACTION</span><span>DEVICE</span><span>DETAIL</span><span>TIME</span></header>{outcomes.length?outcomes.slice(0,20).map((record,i)=>{const o=record.outcome||record;const decision=o.completed===false?'failed':o.decision||o.action||'recorded';return <button className="event-row" type="button" key={record.id||i} onClick={()=>setSelected(record)}><span><i className={decision}/><b>{decision}</b></span><code>{o.action||'—'}</code><span>{record.device_id||o.device_id||'—'}</span><code>{o.error||o.target||o.event_id||'—'}</code><small>{record.created_at||o.time||'—'}</small></button>}):<div className="empty-row">No enforcement outcomes returned.</div>}</div></article>{selected&&<aside className="event-drawer" role="dialog" aria-label="Enforcement event details"><header><div><p className="eyebrow">EVENT DETAIL</p><h3>Enforcement record</h3></div><button type="button" onClick={()=>setSelected(null)}>Close</button></header><pre>{JSON.stringify(selected,null,2)}</pre></aside>}</>}
function ActionForm({ title, copy, fields, submit, successText = 'Action completed successfully.' }) {
  const [message, setMessage] = useState('')
  const handleSubmit = async event => {
    event.preventDefault()
    setMessage('Submitting…')
    try {
      await submit(Object.fromEntries(new FormData(event.currentTarget)))
      setMessage(successText)
    } catch (error) {
      setMessage(`Error: ${error.message}`)
    }
  }
  return <Resource title={title} copy={copy || "Writes require the connected tenant admin credential"}>
    <form className="action-form" onSubmit={handleSubmit}>
      {fields.map(([name,label]) => <label key={name}>{label}<input name={name} required/></label>)}
      <button className="primary">Deploy policy</button>
      {message && <p>{message}</p>}
    </form>
  </Resource>
}
function PanelTitle({title,copy,status}){return <header className="panel-title"><div><h3>{title}</h3><p>{copy}</p></div>{status&&<span><i/>{status}</span>}</header>}
export default function App(){const [view,setView]=useState(()=>sessionStorage.getItem('shield-session')?'dashboard':'landing'),[connection,setConnection]=useState(()=>JSON.parse(sessionStorage.getItem('shield-connection')||'{}'));const connect=x=>{setConnection(x);sessionStorage.setItem('shield-connection',JSON.stringify(x));sessionStorage.setItem('shield-session','1');setView('dashboard')};const logout=async(notice='')=>{if(connection.tenant&&connection.token){try{await new ShieldApi(connection.baseUrl,connection.tenant,connection.token).auth('logout',{tenant_id:connection.tenant})}catch{/* local sign-out still proceeds if the control plane is unavailable */}}if(notice)sessionStorage.setItem('shield-auth-notice',notice);else sessionStorage.removeItem('shield-auth-notice');sessionStorage.removeItem('shield-session');sessionStorage.removeItem('shield-connection');setView(notice?'signin':'landing')};return view==='landing'?<Landing next={()=>setView('signin')}/>:view==='signin'?<SignIn back={()=>setView('landing')} connect={connect}/>:<Dashboard connection={connection} logout={logout}/>}
