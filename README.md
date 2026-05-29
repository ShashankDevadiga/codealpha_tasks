# 🛡️ SHIELD-NIDS — Network Intrusion Detection System Dashboard

A fully interactive, browser-based **Network Intrusion Detection System (NIDS)** dashboard built with pure HTML, CSS, and JavaScript. No frameworks, no backend, no dependencies.

---

## 📁 Project Structure

```
nids_project/
├── index.html        ← Main HTML layout & structure
├── css/
│   └── style.css     ← Dark theme styles & animations
├── js/
│   └── main.js       ← All logic, simulation & interactivity
└── README.md         ← Project documentation
```

---

## 🚀 Features

| Feature | Description |
|---|---|
| 📊 **Live Dashboard** | Real-time packet rate, alert counters, traffic graph |
| 🚨 **Alert System** | Critical / High / Medium / Low severity alerts |
| 📋 **Rule Engine** | Snort/Suricata-style rules with enable/disable toggle |
| 📦 **Packet Capture** | Live packet table with protocol filtering |
| 🌍 **Geo Heatmap** | Top attack source countries |
| 🤖 **Attack Simulation** | Port Scan, SQLi, DoS, Brute Force, XSS |
| 🔒 **Response Actions** | IP Blocking, Rate Limiting, Email Alerts, SIEM |
| 🗺️ **MITRE ATT&CK** | Coverage heatmap across tactics |
| 📈 **Traffic Graph** | Canvas-based live network traffic chart |

---

## 🛠️ Technologies Used

- **HTML5** — Page structure and layout
- **CSS3** — Dark theme, animations, grid/flexbox
- **JavaScript (Vanilla)** — All logic and simulation
- **HTML5 Canvas API** — Live traffic graph

---

## 🖥️ How to Run

### Option 1 — VS Code Live Server (Recommended)
1. Open the `nids_project` folder in **VS Code**
2. Install the **Live Server** extension
3. Right-click `index.html` → **Open with Live Server**
4. Opens at `http://127.0.0.1:5500`

### Option 2 — Direct Browser
- Just double-click `index.html` — opens in any browser instantly

---

## 🎮 How to Use

1. **Dashboard tab** — Watch live traffic and alerts
2. **Attack buttons** — Click ⚡ Port Scan, 💉 SQLi, 🌊 DoS etc. to simulate attacks
3. **Alerts tab** — Filter and search all generated alerts
4. **Rules tab** — Enable/disable detection rules, add custom rules
5. **Packets tab** — Filter live packet capture by protocol
6. **Response tab** — Toggle automated response actions

---

## 📤 GitHub Pages Deployment

After pushing to GitHub:
1. Go to **Settings → Pages**
2. Source: `main` branch → `/ (root)`
3. Your live URL: `https://your-username.github.io/nids-dashboard/`

---

## 👨‍💻 Built for

Network Security / Cybersecurity coursework — NIDS simulation project.
