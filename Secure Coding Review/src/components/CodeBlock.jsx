import { useState } from 'react';

export default function CodeBlock({ code, label }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard?.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div style={{ marginBottom: 12 }}>
      {label && (
        <div style={{
          fontSize: 11,
          color: '#888',
          marginBottom: 4,
          fontFamily: 'JetBrains Mono, monospace',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
        }}>
          {label}
        </div>
      )}
      <div style={{ position: 'relative' }}>
        <pre style={{
          background: '#0d1117',
          border: '1px solid #30363d',
          borderRadius: 6,
          padding: '12px 14px',
          fontSize: 12,
          lineHeight: 1.7,
          color: '#e6edf3',
          fontFamily: 'JetBrains Mono, monospace',
          margin: 0,
          overflowX: 'auto',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
        }}>
          {code}
        </pre>
        <button
          onClick={handleCopy}
          style={{
            position: 'absolute',
            top: 8,
            right: 8,
            background: copied ? '#30d158' : '#21262d',
            color: copied ? '#fff' : '#8b949e',
            border: '1px solid #30363d',
            borderRadius: 4,
            padding: '2px 8px',
            fontSize: 10,
            cursor: 'pointer',
            fontFamily: 'JetBrains Mono, monospace',
          }}
        >
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>
    </div>
  );
}
