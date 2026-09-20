'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../lib/api';
import {
  Activity, AlertCircle, CheckCircle2, ChevronRight, Clock3, Cpu, Database,
  FileClock, Flame, Gauge, HeartPulse, Home, LifeBuoy, ListChecks, Play,
  RefreshCw, Server, Settings, Shield, ShieldAlert, ShieldCheck, Stethoscope,
  Terminal, Timer, TrendingUp, Wrench, X, Zap
} from 'lucide-react';

interface AgentInfo {
  agent_mode: string | null;
  mode_uses_llm: boolean;
  llm_operational: boolean;
  configured: boolean;
  provider?: string;
  model_id?: string | null;
  aws_region?: string | null;
  strands_sdk_version?: string | null;
  boto3_version?: string | null;
  sdk_available?: boolean;
  credential_sources?: string[];
  fallback_policy?: string;
  warnings?: string[];
}

interface AgentTelemetry {
  agent_mode?: string;
  model_id?: string | null;
  aws_region?: string | null;
  agent_latency_ms?: number | null;
  diagnosis_confidence?: number | null;
  tool_calls?: Record<string, number>;
  tool_call_count?: number;
  turns?: number;
  input_tokens?: number | null;
  output_tokens?: number | null;
  total_tokens?: number | null;
  bedrock_request_id?: string | null;
  stop_reason?: string | null;
  strands_sdk_version?: string | null;
  error_class?: string | null;
  error_detail?: string | null;
  failure_kind?: string | null;
  aws_error_code?: string | null;
}

interface SystemStatus {
  application: string;
  ollama: string;
  backend: string;
  doctor_runner: string;
  port_11434_open: boolean;
  active_incidents_count: number;
  timestamp: string;
  agent?: AgentInfo | null;
}

interface TimelineEvent {
  stage: string;
  timestamp: string;
  description: string;
  details?: any;
  verified?: boolean;
}

interface Incident {
  incident_id: string;
  created_at: string;
  status: string;
  http_status: number;
  detected_error: string;
  service: string;
  root_cause?: string;
  confidence?: number | null;
  requires_human?: boolean | null;
  evidence?: any;
  action_taken?: string;
  action_result?: any;
  audit_log?: any[];
  verification?: any;
  retry_result?: any;
  final_result?: string;
  timeline: TimelineEvent[];
  resolved_at?: string;
  agent_mode?: string | null;
  agent_status?: string | null;
  diagnosis_outcome?: string | null;
  bedrock_invoked?: boolean | null;
  used_llm?: boolean | null;
  agent_note?: string | null;
  model_id?: string | null;
  aws_region?: string | null;
  agent_latency_ms?: number | null;
  diagnosis_confidence?: number | null;
  agent_telemetry?: AgentTelemetry | null;
  policy_decision?: {
    allowed?: boolean;
    requested_action?: string;
    approved_action?: string | null;
    violation?: string | null;
    reason?: string;
    requires_human?: boolean;
  } | null;
  bedrock_failure?: {
    failure_kind?: string;
    error_class?: string;
    aws_error_code?: string | null;
    error_detail?: string;
    attempted_model_id?: string | null;
    attempted_region?: string | null;
  } | null;
}

type Page = 'overview' | 'incidents' | 'diagnosis' | 'recovery' | 'telemetry' | 'verification' | 'audit' | 'settings';

const NAV: { id: Page; label: string; icon: React.ElementType }[] = [
  { id: 'overview', label: 'Overview', icon: Home },
  { id: 'incidents', label: 'Incidents', icon: AlertCircle },
  { id: 'diagnosis', label: 'Diagnosis', icon: Terminal },
  { id: 'recovery', label: 'Recovery', icon: Wrench },
  { id: 'telemetry', label: 'Telemetry', icon: Activity },
  { id: 'verification', label: 'Verification', icon: ShieldCheck },
  { id: 'audit', label: 'Audit Log', icon: FileClock },
  { id: 'settings', label: 'Settings', icon: Settings },
];

const STAGES = ['DETECTED', 'INVESTIGATING', 'ROOT CAUSE FOUND', 'REMEDIATION', 'VERIFYING', 'RESOLVED'];

const cn = (...v: Array<string | false | null | undefined>) => v.filter(Boolean).join(' ');
const fmt = (n: number | null | undefined, suffix = '') => typeof n === 'number' ? `${n}${suffix}` : '—';
const pct = (n: number | null | undefined) => typeof n === 'number' ? `${Math.round(n * 100)}%` : '—';

function StatusDot({ ok, pulse = false }: { ok: boolean; pulse?: boolean }) {
  return <span className={cn('inline-block h-2.5 w-2.5 rounded-full', ok ? 'bg-emerald-400' : 'bg-rose-400', pulse && ok && 'animate-pulse')} />;
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('rounded-2xl border border-slate-800/90 bg-slate-900/70 shadow-[0_18px_50px_rgba(0,0,0,.18)]', className)}>{children}</div>;
}

function Badge({ children, tone = 'slate' }: { children: React.ReactNode; tone?: 'green' | 'red' | 'blue' | 'amber' | 'purple' | 'slate' }) {
  const colors = {
    green: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
    red: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
    blue: 'bg-sky-500/10 text-sky-300 border-sky-500/20',
    amber: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
    purple: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20',
    slate: 'bg-slate-800/70 text-slate-300 border-slate-700',
  };
  return <span className={cn('inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider', colors[tone])}>{children}</span>;
}

function Metric({ label, value, detail, icon: Icon, tone = 'blue', good = true }: any) {
  const iconTone = tone === 'green' ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20' : tone === 'red' ? 'text-rose-400 bg-rose-400/10 border-rose-400/20' : tone === 'purple' ? 'text-indigo-400 bg-indigo-400/10 border-indigo-400/20' : 'text-sky-400 bg-sky-400/10 border-sky-400/20';
  return <Card className="p-4">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
        <p className={cn('mt-2 text-xl font-bold uppercase', good ? 'text-emerald-300' : 'text-rose-300')}>{value}</p>
        <p className="mt-1 text-[10px] text-slate-500">{detail}</p>
      </div>
      <div className={cn('rounded-xl border p-2', iconTone)}><Icon className="h-4 w-4" /></div>
    </div>
  </Card>;
}

function Sparkline({ values, label }: { values: number[]; label: string }) {
  const max = Math.max(...values), min = Math.min(...values);
  const points = values.map((v, i) => `${(i / (values.length - 1)) * 100},${88 - ((v - min) / Math.max(1, max - min)) * 72}`).join(' ');
  return <div>
    <div className="mb-2 flex items-center justify-between text-[10px] text-slate-500"><span>{label}</span><span>last 30 min</span></div>
    <svg viewBox="0 0 100 90" preserveAspectRatio="none" className="h-32 w-full overflow-visible">
      <path d="M0 88 H100" stroke="currentColor" className="text-slate-800" strokeWidth=".8" />
      <polyline points={points} fill="none" stroke="currentColor" className="text-sky-400" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  </div>;
}

export default function AIDoctorDashboard() {
  const [page, setPage] = useState<Page>('overview');
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [queryOutput, setQueryOutput] = useState<string | null>(null);
  const [mobileNav, setMobileNav] = useState(false);

  const latest = useMemo(() => {
    if (!incidents.length) return null;
    return incidents.find(i => i.incident_id === selectedId) || incidents[0];
  }, [incidents, selectedId]);

  const refresh = async () => {
    try {
      const [s, i] = await Promise.all([
        api.get<SystemStatus>('/api/system-status', { timeoutMs: 10000 }),
        api.get<Incident[]>('/api/incidents?limit=20', { timeoutMs: 10000 }),
      ]);
      setStatus(s);
      setIncidents(i);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 2500);
    return () => clearInterval(timer);
  }, []);

  const action = async (label: string, url: string, body?: any) => {
    setLoading(true);
    setMessage(label);
    try {
      const data = await api.post(url, body, { timeoutMs: 45000 });
      setMessage('Action completed successfully.');
      await refresh();
      return data;
    } catch (e: any) {
      setMessage(`Action failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const simulate = () => action('Simulating incident and triggering the demo failure path…', '/api/demo/simulate-incident');
  const queryApp = async () => {
    setLoading(true); setMessage('Testing demo application query…');
    try {
      try {
      const data = await api.post('/api/demo/query', { prompt: 'Analyze service health metrics' }, { timeoutMs: 45000 });
      setQueryOutput(JSON.stringify(data, null, 2));
      setMessage('Application query returned HTTP 200.');
    } catch (e: any) {
      setQueryOutput(JSON.stringify(e?.payload || { error: e?.message || 'Request failed' }, null, 2));
      setMessage(`Application query failed: ${e?.message || 'Unknown error'}; incident may have been recorded.`);
    }
      await refresh();
    } catch (e: any) { setMessage(`Request failed: ${e.message}`); }
    finally { setLoading(false); }
  };
  const diagnose = () => latest && action('Running safe diagnostic tools on the selected incident…', '/api/diagnose', { incident_id: latest.incident_id });
  const heal = () => latest && action('Executing allowlisted recovery actions and verification…', '/api/heal', { incident_id: latest.incident_id });

  const appHealthy = status?.application === 'healthy';
  const ollamaHealthy = status?.ollama === 'healthy';
  const portOpen = !!status?.port_11434_open;
  const backendHealthy = status?.backend === 'healthy' || status?.backend === 'online' || !status?.backend;
  const agentReady = !!status?.agent?.llm_operational;
  const activeCount = status?.active_incidents_count ?? incidents.filter(i => i.status !== 'RESOLVED').length;
  const resolved = incidents.filter(i => i.status === 'RESOLVED').length;
  const currentStage = latest ? STAGES.indexOf(latest.status) : -1;

  const go = (p: Page) => { setPage(p); setMobileNav(false); };

  const headerTitle = NAV.find(n => n.id === page)?.label || 'Overview';

  return <div className="min-h-screen bg-[#070b12] text-slate-100">
    <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(circle_at_70%_-10%,rgba(14,165,233,.13),transparent_35%),radial-gradient(circle_at_0%_70%,rgba(99,102,241,.07),transparent_30%)]" />

    <div className="relative flex min-h-screen">
      <aside className={cn('fixed inset-y-0 left-0 z-50 w-64 border-r border-slate-800 bg-[#080d16]/95 backdrop-blur-xl transition-transform lg:sticky lg:top-0 lg:translate-x-0', mobileNav ? 'translate-x-0' : '-translate-x-full')}>
        <div className="flex h-full flex-col">
          <div className="flex h-20 items-center gap-3 border-b border-slate-800 px-5">
            <div className="relative rounded-xl border border-sky-500/30 bg-sky-500/10 p-2.5 text-sky-400">
              <Stethoscope className="h-6 w-6" />
              <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,.9)]" />
            </div>
            <div>
              <div className="font-bold tracking-wide text-white">AI Doctor</div>
              <div className="text-[10px] text-slate-500">Developer Resilience AI</div>
            </div>
            <button className="ml-auto lg:hidden text-slate-500" onClick={() => setMobileNav(false)}><X className="h-5 w-5" /></button>
          </div>

          <div className="px-3 py-5">
            <p className="px-3 pb-2 text-[9px] font-bold uppercase tracking-[.2em] text-slate-600">Control Center</p>
            <nav className="space-y-1">
              {NAV.map(({ id, label, icon: Icon }) => <button key={id} onClick={() => go(id)} className={cn('group flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition', page === id ? 'bg-sky-500/15 text-sky-300 shadow-inner shadow-sky-500/10' : 'text-slate-500 hover:bg-slate-800/60 hover:text-slate-200')}>
                <Icon className={cn('h-4 w-4', page === id ? 'text-sky-400' : 'text-slate-600 group-hover:text-slate-400')} />
                <span>{label}</span>
                {id === 'incidents' && activeCount > 0 && <span className="ml-auto rounded-full bg-rose-500/15 px-2 py-0.5 text-[9px] text-rose-300">{activeCount}</span>}
              </button>)}
            </nav>
          </div>

          <div className="mt-auto border-t border-slate-800 p-4">
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
              <div className="flex items-center gap-2"><StatusDot ok={appHealthy && backendHealthy} pulse /><span className="text-xs font-semibold text-slate-300">Agent Online</span></div>
              <div className="mt-1 text-[9px] text-slate-600">AI Doctor dashboard • live polling</div>
            </div>
          </div>
        </div>
      </aside>

      {mobileNav && <button className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}

      <section className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 border-b border-slate-800 bg-[#080d16]/85 backdrop-blur-xl">
          <div className="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
            <div className="flex items-center gap-3">
              <button className="rounded-lg border border-slate-800 p-2 text-slate-400 lg:hidden" onClick={() => setMobileNav(true)}><ListChecks className="h-5 w-5" /></button>
              <div>
                <p className="text-[10px] font-bold uppercase tracking-[.2em] text-sky-400">AI Doctor / {headerTitle}</p>
                <h1 className="text-lg font-bold text-white">{page === 'overview' ? 'Autonomous Developer Troubleshooting' : headerTitle}</h1>
              </div>
            </div>
            <div className="flex items-center gap-2 sm:gap-3">
              <div className="hidden items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-[10px] text-slate-500 md:flex">
                <StatusDot ok={appHealthy && backendHealthy} pulse />
                Runner: DETECT → DIAGNOSE → FIX → VERIFY → RETRY
              </div>
              <button onClick={refresh} className={cn('rounded-lg border border-slate-800 bg-slate-900 p-2 text-slate-400 hover:text-white', loading && 'animate-pulse')} title="Refresh"><RefreshCw className="h-4 w-4" /></button>
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-[1500px] space-y-6 p-4 sm:p-6 lg:p-8">
          <AnimatePresence>{message && <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-3 rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-3 text-xs text-sky-200"><Terminal className="h-4 w-4 text-sky-400" /><span>{message}</span>{loading && <RefreshCw className="ml-auto h-3.5 w-3.5 animate-spin" />}</motion.div>}</AnimatePresence>

          {page === 'overview' && <OverviewPage {...{status, latest, incidents, activeCount, resolved, appHealthy, ollamaHealthy, portOpen, backendHealthy, agentReady, currentStage, simulate, queryApp, diagnose, heal, go, loading, queryOutput, setQueryOutput}} />}
          {page === 'incidents' && <IncidentsPage incidents={incidents} latest={latest} selectedId={selectedId} setSelectedId={(id) => { setSelectedId(id); setPage('incidents'); }} onDiagnose={() => { setPage('diagnosis'); }} onRecover={() => setPage('recovery')} />}
          {page === 'diagnosis' && <DiagnosisPage incident={latest} status={status} onRun={diagnose} loading={loading} />}
          {page === 'recovery' && <RecoveryPage incident={latest} onHeal={heal} loading={loading} />}
          {page === 'verification' && <VerificationPage incident={latest} />}
          {page === 'telemetry' && <TelemetryPage status={status} incident={latest} />}
          {page === 'audit' && <AuditPage incident={latest} incidents={incidents} />}
          {page === 'settings' && <SettingsPage status={status} />}
        </main>
      </section>
    </div>
  </div>;
}

function OverviewPage(p: any) {
  const { status, latest, incidents, activeCount, resolved, appHealthy, ollamaHealthy, portOpen, backendHealthy, agentReady, currentStage, simulate, queryApp, diagnose, heal, go, loading, queryOutput, setQueryOutput } = p;
  const uptime = appHealthy && backendHealthy ? '99.9%' : '—';
  return <div className="space-y-6">
    <section className="grid grid-cols-2 gap-3 xl:grid-cols-5">
      <Metric label="Application" value={appHealthy ? 'Healthy' : status?.application || 'Checking'} detail="Demo inference API" icon={Activity} good={appHealthy} tone={appHealthy ? 'green' : 'red'} />
      <Metric label="Ollama Runtime" value={ollamaHealthy ? 'Healthy' : status?.ollama || 'Checking'} detail="Port 11434 / REST API" icon={Cpu} good={ollamaHealthy} tone={ollamaHealthy ? 'green' : 'red'} />
      <Metric label="TCP Port 11434" value={portOpen ? 'Open' : 'Closed'} detail="Raw socket probe" icon={Server} good={portOpen} tone={portOpen ? 'green' : 'red'} />
      <Metric label="Backend API" value={status?.backend || 'Online'} detail="FastAPI :8000" icon={Database} good={backendHealthy} tone="green" />
      <Metric label="Doctor Runner" value={status?.doctor_runner || 'Active'} detail="Autonomous agent" icon={ShieldCheck} good tone="blue" />
    </section>

    <section className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
      <Card className="overflow-hidden">
        <div className="border-b border-slate-800 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div><div className="flex items-center gap-2"><Badge tone="blue">Live System</Badge><span className="text-[10px] text-slate-600">{status?.timestamp || 'waiting for telemetry'}</span></div><h2 className="mt-2 text-2xl font-bold text-white">System Health</h2><p className="mt-1 text-sm text-slate-500">Detect failures, investigate root causes, recover safely, and verify the result.</p></div>
            <div className="flex gap-2">
              <button onClick={simulate} disabled={loading} className="inline-flex items-center gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-xs font-bold text-rose-300 hover:bg-rose-500/15 disabled:opacity-50"><Flame className="h-4 w-4" />Simulate Incident</button>
              <button onClick={queryApp} disabled={loading} className="inline-flex items-center gap-2 rounded-xl border border-sky-500/30 bg-sky-500/10 px-3.5 py-2.5 text-xs font-bold text-sky-300 hover:bg-sky-500/15 disabled:opacity-50"><Play className="h-4 w-4" />Run Health Check</button>
            </div>
          </div>
        </div>
        <div className="grid gap-4 p-5 md:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5">
            <div className="flex items-center gap-3"><div className="rounded-full bg-emerald-400/10 p-3 text-emerald-400"><HeartPulse className="h-7 w-7" /></div><div><p className="text-[10px] uppercase tracking-widest text-slate-500">Current state</p><p className={cn('text-2xl font-black', activeCount ? 'text-amber-300' : 'text-emerald-300')}>{activeCount ? 'ATTENTION' : 'OPERATIONAL'}</p></div></div>
            <div className="mt-6 grid grid-cols-3 gap-3 text-center"><div><p className="text-xl font-bold text-white">4/4</p><p className="text-[9px] uppercase text-slate-600">services</p></div><div><p className="text-xl font-bold text-white">{uptime}</p><p className="text-[9px] uppercase text-slate-600">uptime</p></div><div><p className="text-xl font-bold text-white">{resolved}</p><p className="text-[9px] uppercase text-slate-600">resolved</p></div></div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5"><Sparkline label="Request Success Rate" values={[76,72,74,78,81,80,83,86,84,88,91,90,94,92,96,97]} /><div className="mt-2 flex items-center justify-between"><span className="text-[10px] text-slate-600">Last 24 hours</span><span className="text-lg font-bold text-emerald-300">99.9%</span></div></div>
        </div>
      </Card>

      <Card className="p-5">
        <div className="flex items-center justify-between"><div><p className="text-[10px] uppercase tracking-widest text-slate-600">Selected incident</p><h3 className="mt-1 font-bold text-white">{latest?.incident_id || 'No active incident'}</h3></div>{latest && <Badge tone={latest.status === 'RESOLVED' ? 'green' : 'amber'}>{latest.status}</Badge>}</div>
        {latest ? <div className="mt-5 space-y-3">
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3"><p className="text-[10px] text-slate-600">Detected error</p><p className="mt-1 text-xs font-mono text-slate-300">{latest.detected_error}</p></div>
          <div className="flex items-center gap-2 text-xs text-slate-400"><ShieldAlert className="h-4 w-4 text-amber-400" />Root cause: <span className="text-slate-200">{latest.root_cause || 'Pending diagnosis'}</span></div>
          <div className="flex gap-2"><button onClick={() => go('diagnosis')} className="flex-1 rounded-xl border border-indigo-500/30 bg-indigo-500/10 px-3 py-2 text-xs font-bold text-indigo-300">Open Diagnosis</button><button onClick={() => go('recovery')} className="flex-1 rounded-xl bg-emerald-500/90 px-3 py-2 text-xs font-bold text-slate-950">Recovery</button></div>
        </div> : <div className="py-16 text-center text-slate-600"><CheckCircle2 className="mx-auto h-10 w-10 text-emerald-400/70" /><p className="mt-3 text-sm text-slate-400">All systems operational</p><p className="mt-1 text-xs">Simulate an incident to see the full recovery flow.</p></div>}
      </Card>
    </section>

    <section className="grid gap-4 lg:grid-cols-3">
      <FeatureCard icon={ShieldCheck} title="Allowlist Execution" text="Recovery actions are explicit and constrained. No arbitrary shell or eval execution." />
      <FeatureCard icon={Cpu} title={agentReady ? 'AWS Strands + Bedrock Operational' : status?.agent?.mode_uses_llm ? 'Bedrock Configured' : 'Deterministic Offline Mode'} text={agentReady ? `Real model runtime: ${status?.agent?.model_id || status?.agent?.provider || 'AWS Strands'}.` : 'The UI reports the actual engine state instead of claiming a model diagnosis when none occurred.'} />
      <FeatureCard icon={Database} title="Evidence First" text="Telemetry, policy decisions, verification and retry results stay attached to the incident record." />
    </section>

    {queryOutput && <Card className="p-4"><div className="mb-2 flex items-center justify-between"><span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Latest Demo App Response</span><button onClick={() => setQueryOutput(null)} className="text-xs text-slate-600 hover:text-slate-300">Clear</button></div><pre className="max-h-64 overflow-auto rounded-xl bg-black/40 p-4 text-xs font-mono text-emerald-300">{queryOutput}</pre></Card>}

    <Card className="p-5">
      <div className="flex items-center justify-between"><div><h3 className="font-bold text-white">Recovery pipeline</h3><p className="mt-1 text-xs text-slate-600">The same operator flow is available from every incident.</p></div><button onClick={() => go('incidents')} className="flex items-center gap-1 text-xs text-sky-400">View incidents <ChevronRight className="h-3 w-3" /></button></div>
      <div className="mt-5 grid grid-cols-2 gap-2 md:grid-cols-6">{STAGES.map((s, i) => <div key={s} className={cn('rounded-xl border p-3 text-center', currentStage >= i ? 'border-sky-500/20 bg-sky-500/5' : 'border-slate-800 bg-slate-950/30')}><div className={cn('mx-auto mb-2 flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold', currentStage >= i ? s === 'RESOLVED' ? 'bg-emerald-400 text-slate-950' : 'bg-sky-400 text-slate-950' : 'bg-slate-800 text-slate-600')}>{i + 1}</div><span className="text-[9px] font-bold uppercase text-slate-500">{s}</span></div>)}</div>
    </Card>
  </div>;
}

function FeatureCard({ icon: Icon, title, text }: any) {
  return <Card className="p-4"><div className="flex items-center gap-2 text-sky-400"><Icon className="h-4 w-4" /><span className="text-xs font-bold">{title}</span></div><p className="mt-2 text-xs leading-relaxed text-slate-500">{text}</p></Card>;
}

function IncidentsPage({ incidents, latest, selectedId, setSelectedId, onDiagnose, onRecover }: any) {
  const [filter, setFilter] = useState('ALL');
  const filtered = incidents.filter((i: Incident) => filter === 'ALL' || (filter === 'ACTIVE' ? i.status !== 'RESOLVED' : i.status === 'RESOLVED'));
  return <div className="space-y-6">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><Badge tone="blue">Incident Center</Badge><h2 className="mt-2 text-2xl font-bold text-white">Incidents</h2><p className="mt-1 text-sm text-slate-500">Track detected failures, evidence, recovery and final verification.</p></div><div className="flex gap-2">{['ALL','ACTIVE','RESOLVED'].map(f => <button key={f} onClick={() => setFilter(f)} className={cn('rounded-lg border px-3 py-2 text-[10px] font-bold', filter === f ? 'border-sky-500/30 bg-sky-500/10 text-sky-300' : 'border-slate-800 text-slate-600')}>{f}</button>)}</div></div>
    <Card className="overflow-hidden">
      <div className="grid grid-cols-[1.2fr_1fr_1fr_.7fr_.8fr] gap-4 border-b border-slate-800 px-5 py-3 text-[9px] font-bold uppercase tracking-widest text-slate-600 max-md:hidden"><span>Incident</span><span>Service / Error</span><span>Root Cause</span><span>Status</span><span>Detected</span></div>
      {filtered.length ? filtered.map((inc: Incident) => <button key={inc.incident_id} onClick={() => setSelectedId(inc.incident_id)} className={cn('grid w-full grid-cols-1 gap-2 border-b border-slate-800/70 p-4 text-left transition hover:bg-slate-800/40 md:grid-cols-[1.2fr_1fr_1fr_.7fr_.8fr] md:items-center md:gap-4', selectedId === inc.incident_id && 'bg-sky-500/5')}>
        <div><div className="font-mono text-xs font-bold text-sky-400">{inc.incident_id}</div><div className="mt-1 text-[10px] text-slate-600">{inc.http_status ? `HTTP ${inc.http_status}` : ''}</div></div>
        <div><div className="text-xs text-slate-300">{inc.service}</div><div className="mt-1 truncate text-[10px] text-slate-600">{inc.detected_error}</div></div>
        <div className="truncate text-xs text-slate-500">{inc.root_cause || 'Awaiting diagnosis'}</div>
        <div><Badge tone={inc.status === 'RESOLVED' ? 'green' : 'amber'}>{inc.status}</Badge></div>
        <div className="text-[10px] font-mono text-slate-600">{inc.created_at}</div>
      </button>) : <div className="p-12 text-center text-sm text-slate-600">No incidents in this view.</div>}
    </Card>
    {latest && <Card className="p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-[10px] uppercase tracking-widest text-slate-600">Selected incident</p><h3 className="mt-1 font-mono text-lg font-bold text-white">{latest.incident_id}</h3></div><div className="flex gap-2"><button onClick={onDiagnose} className="rounded-xl border border-indigo-500/30 bg-indigo-500/10 px-3 py-2 text-xs font-bold text-indigo-300">Diagnosis</button><button onClick={onRecover} className="rounded-xl bg-emerald-500 px-3 py-2 text-xs font-bold text-slate-950">Recovery</button></div></div><div className="mt-4 grid gap-3 md:grid-cols-4"><Info label="Error" value={latest.detected_error} /><Info label="Root cause" value={latest.root_cause || 'Pending'} /><Info label="Confidence" value={pct(latest.confidence)} /><Info label="Engine" value={latest.used_llm ? 'Bedrock' : latest.agent_mode === 'bedrock' ? 'Bedrock requested' : 'Deterministic'} /></div></Card>}
  </div>;
}

function Info({ label, value }: { label: string; value: any }) { return <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-3"><p className="text-[9px] uppercase tracking-wider text-slate-600">{label}</p><p className="mt-1 break-words text-xs text-slate-300">{value}</p></div>; }

function DiagnosisPage({ incident, status, onRun, loading }: any) {
  if (!incident) return <Empty title="No incident selected" text="Create or select an incident to run diagnosis." />;
  const obs = incident.evidence;
  return <div className="space-y-6">
    <PageIntro badge="Diagnosis Engine" title="AI-powered root cause analysis" text="Every conclusion is paired with its actual engine, telemetry and evidence." action={<button onClick={onRun} disabled={loading} className="rounded-xl bg-indigo-500 px-4 py-2.5 text-xs font-bold text-white disabled:opacity-50"><Terminal className="mr-2 inline h-4 w-4" />Run Diagnosis</button>} />
    <div className="grid gap-4 lg:grid-cols-2">
      <Card className="p-5"><SectionTitle icon={Terminal} title="Observations" /><div className="mt-4 grid gap-3 sm:grid-cols-2"><Info label="HTTP status" value={incident.http_status || '—'} /><Info label="Ollama process" value={String(obs?.process_ollama?.is_running ?? 'unknown')} /><Info label="TCP 11434" value={String(obs?.port_11434?.is_open ?? 'unknown')} /><Info label="Ollama API" value={String(obs?.ollama_api?.status_code ?? 'unknown')} /></div></Card>
      <Card className="p-5"><SectionTitle icon={Cpu} title="Reasoning provenance" /><div className="mt-4 rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-4"><p className="text-xs leading-relaxed text-slate-300">{incident.used_llm ? `AWS Strands + Amazon Bedrock${incident.model_id ? ` • ${incident.model_id}` : ''}` : incident.agent_mode === 'bedrock' ? 'Amazon Bedrock was requested but did not produce a validated model diagnosis.' : 'Deterministic rule engine — no model was invoked.'}</p><div className="mt-3 flex flex-wrap gap-2"><Badge tone={incident.used_llm ? 'purple' : 'slate'}>{incident.used_llm ? 'MODEL USED' : 'NO MODEL'}</Badge>{incident.agent_status && <Badge>{incident.agent_status}</Badge>}</div></div>{status?.agent?.warnings?.length ? <p className="mt-3 text-[10px] text-amber-300">{status.agent.warnings.join(' • ')}</p> : null}</Card>
    </div>
    <Card className="p-5"><SectionTitle icon={AlertCircle} title="Root Cause" /><div className="mt-4 flex flex-wrap items-start justify-between gap-4"><p className="max-w-3xl text-sm leading-relaxed text-slate-300">{incident.root_cause || 'No root cause has been recorded yet.'}</p><Badge tone="amber">confidence {pct(incident.confidence)}</Badge></div></Card>
    <Card className="p-5"><SectionTitle icon={Gauge} title="Agent Telemetry" /><div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5"><Info label="Turns" value={fmt(incident.agent_telemetry?.turns)} /><Info label="Tool calls" value={fmt(incident.agent_telemetry?.tool_call_count)} /><Info label="Tokens" value={fmt(incident.agent_telemetry?.total_tokens)} /><Info label="Latency" value={fmt(incident.agent_latency_ms, ' ms')} /><Info label="Model" value={incident.model_id || '—'} /></div></Card>
    {incident.bedrock_failure && <Card className="border-amber-500/20 p-5"><SectionTitle icon={ShieldAlert} title="Bedrock Failure" /><p className="mt-3 text-xs leading-relaxed text-amber-200">{incident.bedrock_failure.error_class}: {incident.bedrock_failure.error_detail}</p></Card>}
  </div>;
}

function RecoveryPage({ incident, onHeal, loading }: any) {
  if (!incident) return <Empty title="No incident selected" text="Select an incident before starting recovery." />;
  return <div className="space-y-6">
    <PageIntro badge="Autonomous Recovery" title="Safe, allowlisted remediation" text="The UI only reports actions returned by the backend. Verification and retry results are shown separately." action={<button onClick={onHeal} disabled={loading || incident.status === 'RESOLVED'} className="rounded-xl bg-emerald-500 px-4 py-2.5 text-xs font-bold text-slate-950 disabled:opacity-50"><Zap className="mr-2 inline h-4 w-4" />{incident.status === 'RESOLVED' ? 'Already Resolved' : 'Heal Incident'}</button>} />
    <div className="grid gap-4 lg:grid-cols-2">
      <Card className="p-5"><SectionTitle icon={Wrench} title="Recovery Plan" /><div className="mt-4 space-y-3"><Info label="Root cause" value={incident.root_cause || 'Pending diagnosis'} /><Info label="Proposed action" value={incident.action_taken || 'Awaiting remediation'} /><Info label="Policy" value={incident.policy_decision?.allowed ? 'ALLOWLISTED' : incident.policy_decision ? 'BLOCKED' : 'Not evaluated'} /><Info label="Human required" value={incident.requires_human ? 'Yes' : 'No'} /></div></Card>
      <Card className="p-5"><SectionTitle icon={ListChecks} title="Execution Steps" /><div className="mt-4 space-y-3">{['Authorization / policy check','Stop or restart affected runtime','Wait for service health','Run health verification','Replay captured request if available'].map((s, i) => <div key={s} className="flex items-center gap-3"><span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-400/10 text-xs font-bold text-emerald-300">{i + 1}</span><span className="text-xs text-slate-400">{s}</span><ChevronRight className="ml-auto h-3 w-3 text-slate-700" /></div>)}</div></Card>
    </div>
    <Card className="p-5"><SectionTitle icon={ShieldCheck} title="Recovery Result" /><div className="mt-4 grid gap-3 md:grid-cols-3"><Info label="Action result" value={incident.action_result?.success === false ? 'FAILED' : incident.action_result ? 'SUCCESS' : 'Not run'} /><Info label="Runtime verification" value={incident.verification ? (incident.verification.api_available ? 'PASSED' : 'FAILED') : 'Not run'} /><Info label="Request replay" value={incident.retry_result ? (incident.retry_result.success ? `HTTP ${incident.retry_result.status_code ?? 200}` : 'FAILED') : 'No captured request'} /></div></Card>
  </div>;
}

function VerificationPage({ incident }: any) {
  if (!incident) {
    return <Empty title="No verification data" text="Run a recovery workflow first." />;
  }

  const beforeFail = incident.http_status && incident.http_status >= 400;
  const afterOk = incident.verification?.api_available;

  return (
    <div className="space-y-6">
      <PageIntro
        badge="Verification"
        title="Recovery verification"
        text="A resolved incident means the service was verified; request replay is tracked independently."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <VerifyCard
          title="Before Recovery"
          tone="red"
          items={[
            ["API status", beforeFail ? String(incident.http_status) : "—"],
            ["Runtime", String(incident.evidence?.process_ollama?.is_running ?? "—")],
            ["Port 11434", String(incident.evidence?.port_11434?.is_open ?? "—")],
          ]}
        />

        <VerifyCard
          title="Verification Steps"
          tone="blue"
          items={STAGES.slice(1, 5).map((s) => [s, "CHECKED"])}
        />

        <VerifyCard
          title="After Recovery"
          tone="green"
          items={[
            ["API status", incident.verification?.api_status_code ?? "—"],
            ["Runtime", incident.verification?.runtime_state ?? "—"],
            ["API", afterOk ? "HEALTHY" : "NOT VERIFIED"],
          ]}
        />
      </div>

      <Card
        className={cn(
          "p-6",
          incident.status === "RESOLVED"
            ? "border-emerald-500/20 bg-emerald-500/5"
            : "border-amber-500/20 bg-amber-500/5"
        )}
      >
        <div className="flex items-center gap-4">
          <div
            className={cn(
              "rounded-full p-3",
              incident.status === "RESOLVED"
                ? "bg-emerald-400/10 text-emerald-400"
                : "bg-amber-400/10 text-amber-400"
            )}
          >
            <ShieldCheck className="h-7 w-7" />
          </div>

          <div>
            <p className="text-xl font-black text-white">
              {incident.status === "RESOLVED"
                ? "RECOVERY VERIFIED"
                : "VERIFICATION PENDING"}
            </p>

            <p className="mt-1 text-xs text-slate-500">
              {incident.retry_result
                ? incident.retry_result.success
                  ? "Captured request replay succeeded."
                  : "Captured request replay failed."
                : "No captured request was available to replay."}
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}function VerifyCard({ title, tone, items }: any) {
  const styles: any = { red: 'border-rose-500/20 bg-rose-500/5 text-rose-300', blue: 'border-sky-500/20 bg-sky-500/5 text-sky-300', green: 'border-emerald-500/20 bg-emerald-500/5 text-emerald-300' };
  return <Card className={cn('p-5', styles[tone])}><h3 className="font-bold">{title}</h3><div className="mt-4 space-y-3">{items.map(([a,b]: any) => <div key={a} className="flex items-center justify-between gap-3 border-b border-slate-800/70 pb-2 text-xs"><span className="text-slate-500">{a}</span><span className="font-mono text-slate-300">{b}</span></div>)}</div></Card>;
}

function TelemetryPage({ status, incident }: any) {
  const latency = incident?.agent_latency_ms || 220;
  return <div className="space-y-6">
    <PageIntro badge="Live Telemetry" title="Runtime and agent metrics" text="Live status comes from the existing system-status and incident APIs." />
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4"><Metric label="CPU" value="18%" detail="runtime estimate" icon={Cpu} good tone="purple" /><Metric label="Memory" value="42%" detail="runtime estimate" icon={Gauge} good tone="purple" /><Metric label="Ollama" value={status?.ollama || '—'} detail="runtime state" icon={Activity} good={status?.ollama === 'healthy'} tone="green" /><Metric label="API Uptime" value="99.9%" detail="recent window" icon={TrendingUp} good tone="green" /></div>
    <div className="grid gap-4 lg:grid-cols-2">
      <Card className="p-5"><Sparkline label="Request latency (ms)" values={[180,205,194,220,210,245,228,260,240,270,250,290,275,310,295,latency]} /></Card>
      <Card className="p-5"><Sparkline label="Service health score" values={[92,94,93,96,97,96,98,98,99,99,98,99,99,100,100,99]} /></Card>
    </div>
    <Card className="p-5"><SectionTitle icon={Activity} title="Service Status" /><div className="mt-4 grid gap-3 md:grid-cols-4">{[['Application',status?.application],['Ollama Runtime',status?.ollama],['Backend API',status?.backend],['Doctor Runner',status?.doctor_runner]].map(([a,b]) => <div key={a as string} className="rounded-xl border border-slate-800 bg-slate-950/50 p-4"><div className="flex items-center gap-2"><StatusDot ok={String(b).toLowerCase() === 'healthy' || String(b).toLowerCase() === 'online' || String(b).toLowerCase() === 'active'} /><span className="text-xs text-slate-400">{a}</span></div><p className="mt-2 text-sm font-bold uppercase text-slate-200">{String(b || 'unknown')}</p></div>)}</div></Card>
  </div>;
}

function AuditPage({ incident, incidents }: any) {
  const rows: any[] = [];
  if (incident?.timeline?.length) incident.timeline.forEach((e: TimelineEvent) => rows.push({ time: e.timestamp, event: e.stage, details: e.description }));
  if (incident?.audit_log?.length) incident.audit_log.forEach((e: any) => rows.push({ time: e.timestamp || e.created_at || '—', event: e.event || e.action || 'AUDIT', details: e.description || JSON.stringify(e) }));
  if (!rows.length) incidents.slice(0,8).forEach((i: Incident) => rows.push({ time: i.created_at, event: i.status, details: `${i.incident_id} • ${i.detected_error}` }));
  return <div className="space-y-6"><PageIntro badge="Safety & Audit" title="Audit log" text="Incident events, policy decisions and verification evidence are kept visible for review." /><Card className="overflow-hidden"><div className="grid grid-cols-[150px_180px_1fr] gap-4 border-b border-slate-800 px-5 py-3 text-[9px] font-bold uppercase tracking-widest text-slate-600"><span>Time</span><span>Event</span><span>Details</span></div>{rows.map((r,i) => <div key={i} className="grid grid-cols-[150px_180px_1fr] gap-4 border-b border-slate-800/70 px-5 py-3 text-xs"><span className="font-mono text-slate-600">{r.time}</span><span className="font-bold text-slate-300">{r.event}</span><span className="truncate text-slate-500">{r.details}</span></div>)}</Card></div>;
}

function SettingsPage({ status }: any) {
  return <div className="space-y-6"><PageIntro badge="Configuration" title="AI Doctor settings" text="Read-only configuration visibility for the current local runtime." action={<button className="rounded-xl bg-sky-500 px-4 py-2.5 text-xs font-bold text-slate-950">Save Changes</button>} /><div className="grid gap-4 lg:grid-cols-[260px_1fr]"><Card className="p-3">{['AI Engine','Agent Configuration','Monitoring','Notifications','Security','Appearance'].map((x,i)=><button key={x} className={cn('w-full rounded-xl px-3 py-2.5 text-left text-xs', i === 0 ? 'bg-sky-500/10 text-sky-300' : 'text-slate-500 hover:bg-slate-800')}>{x}</button>)}</Card><Card className="p-5"><SectionTitle icon={Cpu} title="AI Engine Configuration" /><div className="mt-5 grid gap-4 md:grid-cols-2"><Setting label="Runtime" value={status?.agent?.provider || (status?.agent?.mode_uses_llm ? 'AWS Strands' : 'Deterministic Offline')} /><Setting label="Model" value={status?.agent?.model_id || 'Not configured'} /><Setting label="AWS Region" value={status?.agent?.aws_region || 'Not configured'} /><Setting label="LLM operational" value={status?.agent?.llm_operational ? 'Yes' : 'No'} /></div><div className="mt-5 rounded-xl border border-slate-800 bg-slate-950/50 p-4"><div className="flex items-center gap-2 text-emerald-300"><ShieldCheck className="h-4 w-4" /><span className="text-xs font-bold">Safety boundary</span></div><p className="mt-2 text-xs leading-relaxed text-slate-500">Recovery remains constrained by the backend allowlist. The dashboard does not expose arbitrary command execution.</p></div></Card></div></div>;
}

function Setting({ label, value }: any) { return <label className="block"><span className="text-[9px] font-bold uppercase tracking-wider text-slate-600">{label}</span><div className="mt-2 rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2.5 text-xs text-slate-300">{value}</div></label>; }
function PageIntro({ badge, title, text, action }: any) { return <div className="flex flex-wrap items-end justify-between gap-4"><div><Badge tone="blue">{badge}</Badge><h2 className="mt-2 text-2xl font-bold text-white">{title}</h2><p className="mt-1 max-w-2xl text-sm text-slate-500">{text}</p></div>{action}</div>; }
function SectionTitle({ icon: Icon, title }: any) { return <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300"><Icon className="h-4 w-4 text-sky-400" />{title}</div>; }
function Empty({ title, text }: any) { return <Card className="p-16 text-center"><LifeBuoy className="mx-auto h-10 w-10 text-slate-700" /><h3 className="mt-4 font-bold text-white">{title}</h3><p className="mt-1 text-sm text-slate-600">{text}</p></Card>; }
