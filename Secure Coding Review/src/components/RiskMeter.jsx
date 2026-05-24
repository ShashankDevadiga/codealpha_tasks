export default function RiskMeter({ score }) {
  const pct = (score / 10) * 100;
  const color = score >= 8 ? '#ff2d55' : score >= 6 ? '#ff9f0a' : '#30d158';

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width={120} height={70} viewBox="0 0 120 70">
        <path
          d="M10 60 A50 50 0 0 1 110 60"
          stroke="#21262d"
          strokeWidth={10}
          fill="none"
          strokeLinecap="round"
        />
        <path
          d="M10 60 A50 50 0 0 1 110 60"
          stroke={color}
          strokeWidth={10}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${pct * 1.57} 157`}
        />
        <text
          x="60" y="56"
          textAnchor="middle"
          fill={color}
          fontSize="22"
          fontWeight="800"
          fontFamily="JetBrains Mono, monospace"
        >
          {score}
        </text>
        <text
          x="60" y="68"
          textAnchor="middle"
          fill="#8b949e"
          fontSize="9"
          fontFamily="JetBrains Mono, monospace"
        >
          /10
        </text>
      </svg>
      <div style={{ fontSize: 11, color: '#8b949e', marginTop: -4 }}>Risk Score</div>
    </div>
  );
}
