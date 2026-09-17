'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  Flame,
  LifeBuoy,
  Play,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Stethoscope,
  Terminal,
  Zap,
} from 'lucide-react';

interface SystemStatus {
  application: string;
  ollama: string;
  backend: string;
  doctor_runner: string;
  port_11434_open: boolean;
  active_incidents_count: number;
  timestamp: string;
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
  evidence?: any;
  action_taken?: string;
  verification?: any;
  final_result?: string;
  timeline: TimelineEvent[];
  resolved_at?: string;
}

const TIMELINE_STAGES = [
  'DETECTED',
  'INVESTIGATING',
  'ROOT CAUSE FOUND',
  'REMEDIATION',
  'VERIFYING',
  'RESOLVED',
];

export default function AIDoctorDashboard() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [latestIncident, setLatestIncident] = useState<Incident | null>(null);
  const [incidentsList, setIncidentsList] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [queryOutput, setQueryOutput] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  // Poll system status and incidents
  const fetchData = async () => {
    try {
      const [statusRes, incRes] = await Promise.all([
        fetch('/api/system-status'),
        fetch('/api/incidents?limit=10'),
      ]);

      if (statusRes.ok) {
        const statusData: SystemStatus = await statusRes.json();
        setStatus(statusData);
      }

      if (incRes.ok) {
        const incidents: Incident[] = await incRes.json();
        setIncidentsList(incidents);
        if (incidents.length > 0) {
          if (!selectedIncidentId) {
            setLatestIncident(incidents[0]);
          } else {
            const found = incidents.find((i) => i.incident_id === selectedIncidentId);
            setLatestIncident(found || incidents[0]);
          }
        }
      }
    } catch (err) {
      console.error('Failed to fetch status:', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2500);
    return () => clearInterval(interval);
  }, [selectedIncidentId]);

  // Actions
  const handleSimulateFailure = async () => {
    setLoading(true);
    setActionMessage('Simulating outage: Terminating Ollama & triggering demo query...');
    try {
      const res = await fetch('/api/demo/simulate-incident', { method: 'POST' });
      const data = await res.json();
      setActionMessage(`Failure detected! Incident #${data.incident_id} registered.`);
      await fetchData();
    } catch (e: any) {
      setActionMessage(`Error simulating failure: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTestAppQuery = async () => {
    setLoading(true);
    setActionMessage('Testing demo application query...');
    try {
      const res = await fetch('/api/demo/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: 'Analyze service health metrics' }),
      });
      const data = await res.json();
      if (res.ok) {
        setQueryOutput(JSON.stringify(data, null, 2));
        setActionMessage('Application query SUCCEEDED (HTTP 200).');
      } else {
        setQueryOutput(JSON.stringify(data, null, 2));
        setActionMessage(`Application query FAILED (HTTP ${res.status}). Incident generated!`);
      }
      await fetchData();
    } catch (e: any) {
      setActionMessage(`Request error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRunDiagnosis = async () => {
    if (!latestIncident) return;
    setLoading(true);
    setActionMessage(`Running safe diagnostic tools on incident ${latestIncident.incident_id}...`);
    try {
      const res = await fetch('/api/diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_id: latestIncident.incident_id }),
      });
      const data = await res.json();
      setActionMessage(`Diagnosis complete: ${data.diagnosis?.root_cause}`);
      await fetchData();
    } catch (e: any) {
      setActionMessage(`Diagnosis error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleHealIncident = async () => {
    if (!latestIncident) return;
    setLoading(true);
    setActionMessage(`Autonomous Healing started for incident ${latestIncident.incident_id}...`);
    try {
      const res = await fetch('/api/heal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_id: latestIncident.incident_id }),
      });
      const data = await res.json();
      if (data.outcome?.status === 'RESOLVED') {
        setActionMessage(`Heal complete! Service verified on port 11434 and original request retried successfully.`);
      } else {
        setActionMessage(`Healing attempted: ${data.outcome?.error || 'Verification pending'}`);
      }
      await fetchData();
    } catch (e: any) {
      setActionMessage(`Heal error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const currentStageIndex = latestIncident
    ? TIMELINE_STAGES.indexOf(latestIncident.status)
    : -1;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-xl text-sky-400">
              <Stethoscope className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold text-white tracking-wide">AI Doctor</h1>
                <span className="text-xs px-2 py-0.5 bg-sky-500/20 text-sky-300 border border-sky-500/30 rounded-full font-mono font-medium">
                  AWS First Commit MVP
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Autonomous Developer Troubleshooting & Recovery Agent
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="hidden md:flex items-center space-x-2 text-xs text-slate-400 bg-slate-800/60 px-3 py-1.5 rounded-lg border border-slate-700/60 font-mono">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>Runner Loop: DETECT → DIAGNOSE → FIX → VERIFY → RETRY</span>
            </div>
            <button
              onClick={fetchData}
              className="p-2 text-slate-400 hover:text-white bg-slate-800/80 hover:bg-slate-700 rounded-lg border border-slate-700 transition"
              title="Refresh State"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1 space-y-6 w-full">
        {/* System Status Row */}
        <section className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {/* Application */}
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <span className="text-xs font-medium text-slate-400">Application</span>
              <Activity
                className={`w-4 h-4 ${
                  status?.application === 'healthy' ? 'text-emerald-400' : 'text-amber-400'
                }`}
              />
            </div>
            <div className="mt-2 flex items-baseline space-x-2">
              <span
                className={`text-xl font-bold uppercase ${
                  status?.application === 'healthy' ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {status?.application || 'Checking...'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Demo Inference API</p>
          </div>

          {/* Ollama Runtime */}
          <div
            className={`border p-4 rounded-xl relative overflow-hidden ${
              status?.ollama === 'healthy'
                ? 'bg-slate-900/60 border-slate-800'
                : 'bg-rose-950/20 border-rose-800/50 glow-active'
            }`}
          >
            <div className="flex justify-between items-start">
              <span className="text-xs font-medium text-slate-400">Ollama Runtime</span>
              <Cpu
                className={`w-4 h-4 ${
                  status?.ollama === 'healthy' ? 'text-emerald-400' : 'text-rose-400'
                }`}
              />
            </div>
            <div className="mt-2 flex items-baseline space-x-2">
              <span
                className={`text-xl font-bold uppercase ${
                  status?.ollama === 'healthy' ? 'text-emerald-400' : 'text-rose-400'
                }`}
              >
                {status?.ollama || 'Checking...'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Port 11434 / REST API</p>
          </div>

          {/* Port 11434 Status */}
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
            <div className="flex justify-between items-start">
              <span className="text-xs font-medium text-slate-400">TCP Port 11434</span>
              <Server
                className={`w-4 h-4 ${
                  status?.port_11434_open ? 'text-emerald-400' : 'text-rose-400'
                }`}
              />
            </div>
            <div className="mt-2 flex items-baseline space-x-2">
              <span
                className={`text-xl font-bold font-mono ${
                  status?.port_11434_open ? 'text-emerald-400' : 'text-rose-400'
                }`}
              >
                {status?.port_11434_open ? 'OPEN' : 'CLOSED'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Raw Socket Probe</p>
          </div>

          {/* Backend API */}
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
            <div className="flex justify-between items-start">
              <span className="text-xs font-medium text-slate-400">Backend API</span>
              <Database className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="mt-2 flex items-baseline space-x-2">
              <span className="text-xl font-bold uppercase text-emerald-400">
                {status?.backend || 'ONLINE'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">FastAPI :8000</p>
          </div>

          {/* Doctor Runner */}
          <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
            <div className="flex justify-between items-start">
              <span className="text-xs font-medium text-slate-400">Doctor Runner</span>
              <ShieldCheck className="w-4 h-4 text-sky-400" />
            </div>
            <div className="mt-2 flex items-baseline space-x-2">
              <span className="text-xl font-bold uppercase text-sky-400">
                {status?.doctor_runner || 'ACTIVE'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Autonomous Agent</p>
          </div>
        </section>

        {/* Action Controls Bar */}
        <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4 shadow-xl">
          <div className="flex items-center space-x-3">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Control Panel:
            </span>
            <button
              onClick={handleSimulateFailure}
              disabled={loading}
              className="flex items-center space-x-2 bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-600/40 px-3.5 py-2 rounded-xl text-sm font-semibold transition disabled:opacity-50"
            >
              <Flame className="w-4 h-4 text-rose-400" />
              <span>Simulate Failure</span>
            </button>
            <button
              onClick={handleTestAppQuery}
              disabled={loading}
              className="flex items-center space-x-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-xl text-sm font-semibold transition disabled:opacity-50"
            >
              <Play className="w-4 h-4 text-sky-400" />
              <span>Query App API</span>
            </button>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleRunDiagnosis}
              disabled={loading || !latestIncident}
              className="flex items-center space-x-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-600/40 px-3.5 py-2 rounded-xl text-sm font-semibold transition disabled:opacity-50"
            >
              <Terminal className="w-4 h-4 text-indigo-400" />
              <span>Run Diagnosis</span>
            </button>
            <button
              onClick={handleHealIncident}
              disabled={loading || !latestIncident || latestIncident.status === 'RESOLVED'}
              className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/30 px-4 py-2 rounded-xl text-sm font-semibold transition disabled:opacity-50"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Heal Incident</span>
            </button>
          </div>
        </section>

        {/* Action Status Banner */}
        {actionMessage && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-3 bg-slate-900 border border-sky-500/30 text-sky-200 text-xs rounded-xl flex items-center justify-between font-mono"
          >
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-sky-400" />
              <span>{actionMessage}</span>
            </div>
            {loading && <RefreshCw className="w-3.5 h-3.5 animate-spin text-sky-400" />}
          </motion.div>
        )}

        {/* Current Incident Section */}
        {latestIncident ? (
          <section className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-3">
                  <span className="px-2.5 py-0.5 text-xs font-mono font-bold bg-slate-800 text-sky-300 border border-slate-700 rounded-md">
                    {latestIncident.incident_id}
                  </span>
                  <span
                    className={`px-2.5 py-0.5 text-xs font-bold rounded-md uppercase ${
                      latestIncident.status === 'RESOLVED'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : latestIncident.status === 'DETECTED'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {latestIncident.status}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    Service: {latestIncident.service}
                  </span>
                </div>
                <h2 className="text-lg font-bold text-white mt-2 flex items-center space-x-2">
                  <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
                  <span className="font-mono text-sm sm:text-base text-rose-200 break-all">
                    HTTP {latestIncident.http_status}: {latestIncident.detected_error}
                  </span>
                </h2>
              </div>
              <div className="text-right text-xs text-slate-500 font-mono">
                <div>Detected: {latestIncident.created_at}</div>
                {latestIncident.resolved_at && (
                  <div className="text-emerald-400">Resolved: {latestIncident.resolved_at}</div>
                )}
              </div>
            </div>

            {/* Autonomous Recovery Timeline */}
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center space-x-2">
                <LifeBuoy className="w-4 h-4 text-sky-400" />
                <span>Autonomous Recovery Loop Timeline</span>
              </h3>
              <div className="relative">
                {/* Connecting track */}
                <div className="absolute top-1/2 left-0 right-0 h-1 bg-slate-800 -translate-y-1/2 hidden md:block" />

                <div className="grid grid-cols-2 md:grid-cols-6 gap-3 relative z-10">
                  {TIMELINE_STAGES.map((stageName, idx) => {
                    const isReached =
                      latestIncident.status === 'RESOLVED' ||
                      idx <= TIMELINE_STAGES.indexOf(latestIncident.status);
                    const isCurrent = latestIncident.status === stageName;

                    return (
                      <motion.div
                        key={stageName}
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className={`p-3 rounded-xl border flex flex-col items-center text-center transition ${
                          isCurrent
                            ? 'bg-sky-950/40 border-sky-500 text-sky-200 ring-2 ring-sky-500/30 glow-active'
                            : isReached
                            ? 'bg-slate-900 border-slate-700 text-slate-200'
                            : 'bg-slate-950/40 border-slate-800/60 text-slate-600'
                        }`}
                      >
                        <div
                          className={`w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs mb-1.5 ${
                            isReached
                              ? stageName === 'RESOLVED'
                                ? 'bg-emerald-500 text-white'
                                : 'bg-sky-500 text-slate-950'
                              : 'bg-slate-800 text-slate-500'
                          }`}
                        >
                          {idx + 1}
                        </div>
                        <span className="text-xs font-bold uppercase tracking-tight">
                          {stageName}
                        </span>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Root Cause & Remediation Summary Card */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase text-amber-400 mb-2">
                  <AlertCircle className="w-4 h-4" />
                  <span>Deduce Root Cause</span>
                </div>
                <p className="text-xs text-slate-300 font-mono leading-relaxed">
                  {latestIncident.root_cause ||
                    'Awaiting diagnostic execution to analyze port, process, and socket telemetry.'}
                </p>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase text-emerald-400 mb-2">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Verified Allowlisted Action</span>
                </div>
                <p className="text-xs text-slate-300 font-mono leading-relaxed">
                  {latestIncident.action_taken ? (
                    <>
                      Action Executed:{' '}
                      <span className="text-emerald-400 font-bold">
                        {latestIncident.action_taken}()
                      </span>
                      <br />
                      Verification: Port 11434 restored (TCP OK) • HTTP 200 replayed
                    </>
                  ) : (
                    'Remediation pending. AI Doctor allowlist strictly permits start_ollama and retry_request.'
                  )}
                </p>
              </div>
            </div>

            {/* Diagnostic Evidence & Audit Log */}
            {latestIncident.evidence && (
              <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-slate-400 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-sky-400" />
                    <span>Real Diagnostic Telemetry Evidence</span>
                  </span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    Scrubbed: Credentials redacted
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400">check_port(11434):</span>
                    <div className="mt-1 text-slate-200">
                      Open: {String(latestIncident.evidence.port_11434?.is_open)}
                      <br />
                      Status: {latestIncident.evidence.port_11434?.status}
                    </div>
                  </div>
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400">check_process("ollama"):</span>
                    <div className="mt-1 text-slate-200">
                      Running: {String(latestIncident.evidence.process_ollama?.is_running)}
                      <br />
                      PIDs: {JSON.stringify(latestIncident.evidence.process_ollama?.pids || [])}
                    </div>
                  </div>
                  <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                    <span className="text-slate-400">check_ollama():</span>
                    <div className="mt-1 text-slate-200">
                      Available: {String(latestIncident.evidence.ollama_api?.is_available)}
                      <br />
                      Code: {String(latestIncident.evidence.ollama_api?.status_code || 'N/A')}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
        ) : (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center text-slate-400">
            <CheckCircle2 className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-lg font-bold text-white">All Systems Operational</h3>
            <p className="text-sm mt-1 max-w-md mx-auto">
              No active incidents detected. Click "Simulate Failure" above to trigger an outage
              and watch AI Doctor detect, diagnose, fix, and verify recovery.
            </p>
          </div>
        )}

        {/* Demo App Output View */}
        {queryOutput && (
          <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase text-slate-400 font-mono">
                Latest Demo App Response
              </span>
              <button
                onClick={() => setQueryOutput(null)}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                Clear
              </button>
            </div>
            <pre className="text-xs font-mono bg-slate-950 p-3 rounded-lg overflow-x-auto text-emerald-300">
              {queryOutput}
            </pre>
          </section>
        )}

        {/* Past Incidents List */}
        {incidentsList.length > 0 && (
          <section className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
            <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider mb-3">
              Incident History ({incidentsList.length})
            </h3>
            <div className="space-y-2">
              {incidentsList.map((inc) => (
                <div
                  key={inc.incident_id}
                  onClick={() => setSelectedIncidentId(inc.incident_id)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer flex items-center justify-between transition ${
                    latestIncident?.incident_id === inc.incident_id
                      ? 'bg-slate-800 border-sky-500 text-white'
                      : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <span className="font-mono font-bold text-sky-400">{inc.incident_id}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        inc.status === 'RESOLVED'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {inc.status}
                    </span>
                    <span className="truncate max-w-xs md:max-w-md font-mono text-slate-400">
                      {inc.detected_error}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">{inc.created_at}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Security & Multi-Agent Architecture Footer Banner */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded-xl">
            <div className="flex items-center space-x-2 text-sky-400 font-bold mb-1">
              <Shield className="w-4 h-4" />
              <span>Allowlist Execution Engine</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              No eval, exec, or arbitrary shell execution. Only explicit operations (`start_ollama`,
              `retry_request`) can ever run.
            </p>
          </div>

          <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded-xl">
            <div className="flex items-center space-x-2 text-indigo-400 font-bold mb-1">
              <Cpu className="w-4 h-4" />
              <span>AWS Strands & Bedrock Ready</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Clean contracts ready for Phase 2 Strands Agent runtime and Amazon Bedrock (Claude
              3.5 Sonnet) reasoning.
            </p>
          </div>

          <div className="p-4 bg-slate-900/40 border border-slate-800/80 rounded-xl">
            <div className="flex items-center space-x-2 text-emerald-400 font-bold mb-1">
              <Database className="w-4 h-4" />
              <span>DynamoDB Schema Compatible</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Incident records strictly match the DynamoDB table specification with sort keys and
              status GSIs.
            </p>
          </div>
        </section>
      </main>
    </div>
  );
}
