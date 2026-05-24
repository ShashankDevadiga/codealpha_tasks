import { SEVERITY_STYLE } from '../data/vulnerabilities';

export default function SeverityBadge({ sev }) {
  const s = SEVERITY_STYLE[sev];
  return (
    <span style={{
      background: s.bg,
      color: s.text,
      fontSize: 10,
      fontWeight: 700,
      letterSpacing: '0.08em',
      padding: '2px 8px',
      borderRadius: 3,
      fontFamily: 'JetBrains Mono, monospace',
      textTransform: 'uppercase',
    }}>
      {sev}
    </span>
  );
}
