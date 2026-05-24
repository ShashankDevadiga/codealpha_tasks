import { useState } from 'react';
import SeverityBadge from './SeverityBadge';
import CodeBlock from './CodeBlock';
import { OWASP_COLORS } from '../data/vulnerabilities';

export default function VulnDetail({ v, onClose }) {
  const [tab, setTab] = useState('overview');
  const tabs = ['overview', 'code', 'remediation'];

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0,
        background: 'rgba(0,0,0,0.8)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: '#161b22',
          border: '1px solid #30363d',
          borderRadius: 12,
          width: '100%',
          maxWidth: 760,
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: 28,
          position: 'relative',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#8b949e' }}>{v.id}</span>
              <SeverityBadge sev={v.severity} />
              <span style={{ fontSize: 11, color: OWASP_COLORS[v.owasp] || '#888', fontFamily: 'JetBrains Mono, monospace' }}>{v.owasp}</span>
              <span style={{ fontSize: 11, color: '#8b949e', fontFamily: 'JetBrains Mono, monospace' }}>{v.cwe}</span>
            </div>
            <h2 style={{ margin: 0, fontSize: 20, color: '#e6edf3', fontWeight: 700 }}>{v.title}</h2>
            <div style={{ marginTop: 4, fontSize: 12, color: '#8b949e' }}>
              Line {v.line} · <span style={{ color: '#58a6ff' }}>{v.endpoint}</span> · Detected by {v.tool}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: '1px solid #30363d',
              borderRadius: 6, color: '#8b949e',
              fontSize: 18, cursor: 'pointer',
              padding: '2px 10px', lineHeight: 1.4,
            }}
          >✕</button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 2, marginBottom: 20, borderBottom: '1px solid #21262d' }}>
          {tabs.map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '8px 16px',
                color: tab === t ? '#58a6ff' : '#8b949e',
                borderBottom: tab === t ? '2px solid #58a6ff' : '2px solid transparent',
                fontSize: 13, fontWeight: tab === t ? 600 : 400,
                textTransform: 'capitalize', fontFamily: 'inherit',
              }}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Tab: Overview */}
        {tab === 'overview' && (
          <div>
            <p style={{ color: '#c9d1d9', lineHeight: 1.7, fontSize: 14, marginTop: 0 }}>{v.description}</p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {[
                ['OWASP Category', v.owaspLabel],
                ['CWE', v.cwe],
                ['Detection Tool', v.tool],
                ['Affected Endpoint', v.endpoint],
                ['Source Line', `Line ${v.line}`],
                ['Severity', v.severity],
              ].map(([k, val]) => (
                <div key={k} style={{ background: '#0d1117', borderRadius: 6, padding: '10px 14px', border: '1px solid #21262d' }}>
                  <div style={{ fontSize: 10, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 3 }}>{k}</div>
                  <div style={{ fontSize: 13, color: '#e6edf3', fontWeight: 600 }}>{val}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab: Code */}
        {tab === 'code' && (
          <div>
            <CodeBlock label="❌ Vulnerable Code" code={v.vulnerable} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '16px 0 12px' }}>
              <div style={{ flex: 1, height: 1, background: '#30363d' }} />
              <span style={{ fontSize: 11, color: '#30d158', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>SECURE REPLACEMENT</span>
              <div style={{ flex: 1, height: 1, background: '#30363d' }} />
            </div>
            <CodeBlock label="✅ Remediated Code" code={v.fixed} />
          </div>
        )}

        {/* Tab: Remediation */}
        {tab === 'remediation' && (
          <div>
            <div style={{ fontSize: 13, color: '#8b949e', marginBottom: 14 }}>Recommended actions to remediate this vulnerability:</div>
            {v.recommendations.map((r, i) => (
              <div
                key={i}
                style={{
                  display: 'flex', gap: 12, alignItems: 'flex-start',
                  padding: '10px 0',
                  borderBottom: i < v.recommendations.length - 1 ? '1px solid #21262d' : 'none',
                }}
              >
                <div style={{
                  width: 22, height: 22, borderRadius: '50%',
                  background: '#1f6feb22', border: '1px solid #1f6feb',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: '#58a6ff', fontSize: 11, fontWeight: 700, flexShrink: 0,
                }}>
                  {i + 1}
                </div>
                <div style={{ fontSize: 14, color: '#c9d1d9', lineHeight: 1.6 }}>{r}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
