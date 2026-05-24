import { useState } from 'react';
import { VULNERABILITIES, SEVERITY_STYLE, OWASP_COLORS } from './data/vulnerabilities';
import SeverityBadge from './components/SeverityBadge';
import RiskMeter from './components/RiskMeter';
import VulnDetail from './components/VulnDetail';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function App() {
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('severity');

  const severityCounts = VULNERABILITIES.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {});

  const owaspMap = VULNERABILITIES.reduce((acc, v) => {
    if (!acc[v.owasp]) acc[v.owasp] = { label: v.owaspLabel, count: 0 };
    acc[v.owasp].count++;
    return acc;
  }, {});

  const filtered = VULNERABILITIES
    .filter(v => filter === 'ALL' || v.severity === filter)
    .filter(v =>
      !search ||
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.owasp.includes(search) ||
      v.cwe.toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) =>
      sortBy === 'severity'
        ? SEV_ORDER[a.severity] - SEV_ORDER[b.severity]
        : a.line - b.line
    );

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0d1117',
      fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
      color: '#c9d1d9',
    }}>
      {/* ── Top Bar ── */}
      <div style={{
        background: '#161b22',
        borderBottom: '1px solid #21262d',
        padding: '14px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 8,
            background: 'linear-gradient(135deg,#ff2d55,#ff9f0a)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 16,
          }}>🔐</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#e6edf3' }}>SecureAudit</div>
            <div style={{ fontSize: 11, color: '#8b949e' }}>Static Code Analysis Report</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: '#8b949e' }}>Target Application</div>
            <div style={{ fontSize: 12, color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace' }}>
              vulnerable_app.py · Flask/Python
            </div>
          </div>
          <div style={{ width: 1, height: 32, background: '#30363d' }} />
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 11, color: '#8b949e' }}>Audit Date</div>
            <div style={{ fontSize: 12, color: '#e6edf3', fontFamily: 'JetBrains Mono, monospace' }}>
              {new Date().toLocaleDateString('en-GB')}
            </div>
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '24px 28px' }}>

        {/* ── Summary Cards ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr 1fr 1fr auto',
          gap: 14,
          marginBottom: 24,
          alignItems: 'stretch',
        }}>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <div
              key={sev}
              onClick={() => setFilter(filter === sev ? 'ALL' : sev)}
              style={{
                background: '#161b22',
                border: `1px solid ${filter === sev ? SEVERITY_STYLE[sev].bg : '#21262d'}`,
                borderRadius: 10,
                padding: '16px 20px',
                cursor: 'pointer',
                transition: 'border-color 0.15s',
                boxShadow: filter === sev ? `0 0 0 1px ${SEVERITY_STYLE[sev].bg}33` : 'none',
              }}
            >
              <div style={{
                fontSize: 28, fontWeight: 800,
                color: SEVERITY_STYLE[sev].bg,
                fontFamily: 'JetBrains Mono, monospace',
                lineHeight: 1,
              }}>
                {severityCounts[sev] || 0}
              </div>
              <div style={{ fontSize: 11, color: '#8b949e', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                {sev}
              </div>
              <div style={{ marginTop: 8, height: 3, borderRadius: 2, background: '#21262d' }}>
                <div style={{
                  height: '100%', borderRadius: 2,
                  background: SEVERITY_STYLE[sev].bg,
                  width: `${((severityCounts[sev] || 0) / 8) * 100}%`,
                }} />
              </div>
            </div>
          ))}
          <div style={{
            background: '#161b22',
            border: '1px solid #21262d',
            borderRadius: 10,
            padding: '8px 20px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minWidth: 140,
          }}>
            <RiskMeter score={8.7} />
          </div>
        </div>

        {/* ── OWASP Coverage ── */}
        <div style={{
          background: '#161b22',
          border: '1px solid #21262d',
          borderRadius: 10,
          padding: '16px 20px',
          marginBottom: 24,
        }}>
          <div style={{
            fontSize: 12, color: '#8b949e', marginBottom: 12,
            textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600,
          }}>
            OWASP Top 10 Coverage
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {Object.entries(owaspMap).map(([code, { label, count }]) => (
              <div key={code} style={{
                background: '#0d1117',
                border: `1px solid ${OWASP_COLORS[code]}44`,
                borderRadius: 6,
                padding: '6px 12px',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: OWASP_COLORS[code],
                  flexShrink: 0, display: 'inline-block',
                }} />
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: OWASP_COLORS[code] }}>{code}</span>
                <span style={{ fontSize: 12, color: '#c9d1d9' }}>{label}</span>
                <span style={{ fontSize: 11, color: '#8b949e' }}>×{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Toolbar ── */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            placeholder="Search by name, OWASP, CWE…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              flex: 1, minWidth: 200,
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: 7,
              padding: '8px 12px',
              color: '#e6edf3',
              fontSize: 13, outline: 'none',
              fontFamily: 'inherit',
            }}
          />
          <div style={{ display: 'flex', gap: 4 }}>
            {FILTERS.map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  background: filter === f ? (SEVERITY_STYLE[f]?.bg || '#1f6feb') : '#161b22',
                  color: filter === f ? '#fff' : '#8b949e',
                  border: `1px solid ${filter === f ? (SEVERITY_STYLE[f]?.bg || '#1f6feb') : '#30363d'}`,
                  borderRadius: 6,
                  padding: '6px 12px',
                  fontSize: 11, cursor: 'pointer',
                  fontWeight: 600,
                  fontFamily: 'JetBrains Mono, monospace',
                  textTransform: 'uppercase',
                }}
              >
                {f}
              </button>
            ))}
          </div>
          <select
            value={sortBy}
            onChange={e => setSortBy(e.target.value)}
            style={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: 6,
              padding: '7px 10px',
              color: '#c9d1d9',
              fontSize: 12, cursor: 'pointer',
              outline: 'none', fontFamily: 'inherit',
            }}
          >
            <option value="severity">Sort: Severity</option>
            <option value="line">Sort: Line Number</option>
          </select>
          <div style={{ fontSize: 12, color: '#8b949e' }}>
            {filtered.length} finding{filtered.length !== 1 ? 's' : ''}
          </div>
        </div>

        {/* ── Findings Table ── */}
        <div style={{ background: '#161b22', border: '1px solid #21262d', borderRadius: 10, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #21262d' }}>
                {['ID', 'Severity', 'Vulnerability', 'OWASP', 'CWE', 'Endpoint', 'Line', 'Tool', ''].map(h => (
                  <th key={h} style={{
                    padding: '10px 14px', textAlign: 'left',
                    fontSize: 10, color: '#8b949e',
                    textTransform: 'uppercase', letterSpacing: '0.1em',
                    fontWeight: 600, background: '#0d1117',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((v, i) => (
                <tr
                  key={v.id}
                  onClick={() => setSelected(v)}
                  style={{
                    borderBottom: i < filtered.length - 1 ? '1px solid #21262d' : 'none',
                    cursor: 'pointer',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = '#1c2128'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '11px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#8b949e' }}>{v.id}</td>
                  <td style={{ padding: '11px 14px' }}><SeverityBadge sev={v.severity} /></td>
                  <td style={{ padding: '11px 14px', fontSize: 13, color: '#e6edf3', fontWeight: 600 }}>{v.title}</td>
                  <td style={{ padding: '11px 14px' }}>
                    <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: OWASP_COLORS[v.owasp] || '#888' }}>{v.owasp}</span>
                  </td>
                  <td style={{ padding: '11px 14px', fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e' }}>{v.cwe}</td>
                  <td style={{ padding: '11px 14px', fontSize: 12, color: '#58a6ff', fontFamily: 'JetBrains Mono, monospace' }}>{v.endpoint}</td>
                  <td style={{ padding: '11px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#8b949e' }}>{v.line}</td>
                  <td style={{ padding: '11px 14px', fontSize: 11, color: '#8b949e' }}>{v.tool}</td>
                  <td style={{ padding: '11px 14px' }}>
                    <span style={{ fontSize: 11, color: '#58a6ff' }}>View →</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ── Best Practices ── */}
        <div style={{ marginTop: 24, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
          {[
            {
              icon: '🛡️', title: 'Input Validation',
              tips: ['Validate all inputs server-side', 'Use allowlists, not denylists', 'Reject unexpected data types and lengths'],
            },
            {
              icon: '🔑', title: 'Secrets Management',
              tips: ['Use environment variables or vaults', 'Rotate credentials regularly', 'Never commit secrets to version control'],
            },
            {
              icon: '🔒', title: 'Secure Defaults',
              tips: ['Disable debug in production', 'Enable HTTPS everywhere', 'Set Secure, HttpOnly, SameSite cookies'],
            },
          ].map(bp => (
            <div key={bp.title} style={{
              background: '#161b22',
              border: '1px solid #21262d',
              borderRadius: 10,
              padding: '16px 18px',
            }}>
              <div style={{ fontSize: 18, marginBottom: 8 }}>{bp.icon}</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#e6edf3', marginBottom: 10 }}>{bp.title}</div>
              {bp.tips.map(t => (
                <div key={t} style={{
                  fontSize: 12, color: '#8b949e',
                  display: 'flex', alignItems: 'flex-start',
                  gap: 6, marginBottom: 5,
                }}>
                  <span style={{ color: '#30d158', flexShrink: 0 }}>✓</span>{t}
                </div>
              ))}
            </div>
          ))}
        </div>

        <div style={{ textAlign: 'center', marginTop: 20, fontSize: 11, color: '#484f58' }}>
          Tools used: Bandit · Semgrep · Manual Review — OWASP Top 10 2021 · CVSSv3 Scoring
        </div>
      </div>

      {selected && <VulnDetail v={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
