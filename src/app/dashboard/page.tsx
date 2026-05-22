'use client';
import { useState, useEffect, useCallback } from 'react';

interface AuditLog {
  hash: string;
  time: string;
  txHash?: string;
}

interface InferenceResult {
  summary: string;
  suggestedBillingCode: string;
  confidence: number;
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState({
    apiCalls: 12450,
    activeAgents: 4,
    itkEfficiency: '99.9%'
  });

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [inferenceLoading, setInferenceLoading] = useState(false);
  const [inferenceResult, setInferenceResult] = useState<InferenceResult | null>(null);
  const [inferenceAudit, setInferenceAudit] = useState<{ dataHash: string; transactionHash: string } | null>(null);
  const [clinicalInput, setClinicalInput] = useState('Patient reports persistent sore throat, mild fever (100.4°F), and difficulty swallowing for 3 days.');
  const [promptInput, setPromptInput] = useState('Summarize the clinical presentation and suggest a billing code.');

  useEffect(() => {
    const interval = setInterval(() => {
      const mockHash = "0x" + Math.random().toString(16).substring(2, 10) + "..." + Math.random().toString(16).substring(2, 10);
      setLogs(prev => [{ hash: mockHash, time: new Date().toLocaleTimeString() }, ...prev].slice(0, 8));
      setMetrics(prev => ({ ...prev, apiCalls: prev.apiCalls + 1 }));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  const runInference = useCallback(async () => {
    setInferenceLoading(true);
    setInferenceResult(null);
    setInferenceAudit(null);

    try {
      const res = await fetch('/api/inference', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agentAddress: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
          clinicalData: { note: clinicalInput },
          prompt: promptInput,
        }),
      });
      const data = await res.json();

      if (data.success) {
        setInferenceResult(data.inference);
        setInferenceAudit(data.audit);
        setLogs(prev => [{
          hash: data.audit.dataHash.substring(0, 18) + '...',
          time: new Date().toLocaleTimeString(),
          txHash: data.audit.transactionHash,
        }, ...prev].slice(0, 8));
        setMetrics(prev => ({ ...prev, apiCalls: prev.apiCalls + 1 }));
      }
    } catch (err) {
      console.error('Inference failed:', err);
    } finally {
      setInferenceLoading(false);
    }
  }, [clinicalInput, promptInput]);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 font-sans">
      {/* Header */}
      <header className="sticky top-0 z-10 bg-white/80 backdrop-blur-md border-b border-slate-200 px-4 md:px-8 py-4">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center">
          <h1 className="text-2xl font-bold text-slate-900 mb-2 md:mb-0">
            <span className="inline-block w-3 h-3 rounded-full bg-teal-500 mr-2 animate-pulse" />
            Shield <span className="text-teal-600">Command Center</span>
          </h1>
          <div className="flex items-center space-x-4">
            <div className="text-sm font-medium text-slate-500 bg-white px-4 py-2 rounded-full border border-slate-200 shadow-sm">
              Network: <span className="text-teal-600 font-bold">ITK Testnet</span>
            </div>
            <a href="/" className="text-sm text-slate-400 hover:text-teal-600 transition-colors">← Home</a>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 md:px-8 py-8">
        {/* Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200 hover:shadow-md transition-shadow group">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">Secure API Calls</h2>
            <p className="text-4xl font-bold text-slate-900 tabular-nums">{metrics.apiCalls.toLocaleString()}</p>
            <div className="mt-2 h-1 w-full bg-slate-100 rounded-full overflow-hidden">
              <div className="h-full bg-teal-500 rounded-full transition-all duration-1000" style={{ width: '78%' }} />
            </div>
          </div>
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200 hover:shadow-md transition-shadow">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">Active SovereignAgents</h2>
            <p className="text-4xl font-bold text-slate-900">{metrics.activeAgents}</p>
            <p className="mt-2 text-xs text-teal-600 font-medium">All agents compliant ✓</p>
          </div>
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200 hover:shadow-md transition-shadow">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">Network Efficiency (ITK)</h2>
            <p className="text-4xl font-bold text-teal-600">{metrics.itkEfficiency}</p>
            <p className="mt-2 text-xs text-slate-500">Paymaster gas subsidy active</p>
          </div>
        </div>

        {/* Secure Inference Widget */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 mb-8 overflow-hidden">
          <div className="bg-gradient-to-r from-teal-600 to-cyan-600 px-6 py-4">
            <h2 className="text-lg font-bold text-white">Run Secure Inference</h2>
            <p className="text-teal-100 text-sm">Submit clinical data through the Zero-Knowledge execution pipeline</p>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-2">Clinical Data (PHI — never leaves server)</label>
                <textarea
                  value={clinicalInput}
                  onChange={(e) => setClinicalInput(e.target.value)}
                  className="w-full h-28 p-3 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent resize-none"
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-2">AI Prompt</label>
                <textarea
                  value={promptInput}
                  onChange={(e) => setPromptInput(e.target.value)}
                  className="w-full h-28 p-3 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent resize-none"
                />
              </div>
            </div>

            <button
              onClick={runInference}
              disabled={inferenceLoading}
              className="mt-4 px-6 py-3 bg-teal-600 text-white rounded-lg font-semibold shadow-md hover:bg-teal-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {inferenceLoading ? (
                <span className="flex items-center"><span className="animate-spin mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full" /> Executing...</span>
              ) : (
                '⚡ Execute Blind Inference'
              )}
            </button>

            {/* Results */}
            {inferenceResult && (
              <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-slate-700 mb-2">AI Response</h3>
                  <p className="text-sm text-slate-800 mb-3">{inferenceResult.summary}</p>
                  <div className="flex space-x-4 text-xs">
                    <span className="bg-teal-100 text-teal-700 px-2 py-1 rounded-full font-medium">Code: {inferenceResult.suggestedBillingCode}</span>
                    <span className="bg-blue-100 text-blue-700 px-2 py-1 rounded-full font-medium">Confidence: {(inferenceResult.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>
                {inferenceAudit && (
                  <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs">
                    <h3 className="text-teal-400 font-semibold mb-2">On-Chain Audit Proof</h3>
                    <div className="text-slate-400 mb-1">Data Hash:</div>
                    <div className="text-teal-300 break-all mb-3">{inferenceAudit.dataHash}</div>
                    <div className="text-slate-400 mb-1">Transaction:</div>
                    <div className="text-cyan-300 break-all">{inferenceAudit.transactionHash}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Bottom Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Live Logs */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <h2 className="text-lg font-bold text-slate-900 mb-1">Live Blockchain Data Streams</h2>
            <p className="text-xs text-slate-500 mb-4">AuditShield.sol cryptographic verification logs</p>
            <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs text-teal-400 h-64 overflow-y-auto shadow-inner">
              {logs.map((log, i) => (
                <div key={i} className="mb-2 border-b border-slate-700/50 pb-2">
                  <span className="text-slate-500">[{log.time}]</span>{' '}
                  <span className="text-slate-400">LOG_ANCHORED</span>{' '}
                  <span className="text-teal-300">{log.hash}</span>
                  {log.txHash && <span className="text-cyan-500 ml-2 text-[10px]">tx:{log.txHash.substring(0, 14)}...</span>}
                </div>
              ))}
              {logs.length === 0 && <div className="text-slate-500 italic">Waiting for transactions...</div>}
            </div>
          </div>

          {/* Identity Management */}
          <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
            <h2 className="text-lg font-bold text-slate-900 mb-1">Identity Management</h2>
            <p className="text-xs text-slate-500 mb-4">Deployed SovereignAgents and ReputationSBT integrity</p>

            <div className="space-y-3">
              <div className="flex justify-between items-center p-4 bg-slate-50 rounded-lg border border-slate-100 hover:bg-slate-100 transition-colors cursor-pointer">
                <div>
                  <h4 className="font-semibold text-slate-800 text-sm">ScribeAgent-Alpha</h4>
                  <p className="text-[10px] text-slate-400 font-mono mt-1">0x71C7656EC7ab88b098defB751B7401B5f6d8976F</p>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-teal-600">98 / 100</div>
                  <div className="text-[10px] text-teal-600 font-medium">SBT Valid ✓</div>
                </div>
              </div>
              <div className="flex justify-between items-center p-4 bg-slate-50 rounded-lg border border-slate-100 hover:bg-slate-100 transition-colors cursor-pointer">
                <div>
                  <h4 className="font-semibold text-slate-800 text-sm">BillingBot-Beta</h4>
                  <p className="text-[10px] text-slate-400 font-mono mt-1">0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db</p>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-amber-500">82 / 100</div>
                  <div className="text-[10px] text-amber-600 font-medium">⚠ Slashing Risk</div>
                </div>
              </div>
              <div className="flex justify-between items-center p-4 bg-slate-50 rounded-lg border border-slate-100 hover:bg-slate-100 transition-colors cursor-pointer">
                <div>
                  <h4 className="font-semibold text-slate-800 text-sm">TriageAgent-Gamma</h4>
                  <p className="text-[10px] text-slate-400 font-mono mt-1">0xdD2FD4581271e230360230F9337D5c0430Bf44C0</p>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-teal-600">95 / 100</div>
                  <div className="text-[10px] text-teal-600 font-medium">SBT Valid ✓</div>
                </div>
              </div>
              <div className="flex justify-between items-center p-4 bg-red-50 rounded-lg border border-red-200 hover:bg-red-100 transition-colors cursor-pointer">
                <div>
                  <h4 className="font-semibold text-slate-800 text-sm">AmbientScribe-Delta</h4>
                  <p className="text-[10px] text-slate-400 font-mono mt-1">0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199</p>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-red-600">34 / 100</div>
                  <div className="text-[10px] text-red-600 font-medium">✖ SLASHED — Revoked</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
