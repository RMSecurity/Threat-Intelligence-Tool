# RMSecurity — Cyber Threat Intelligence Tool

> Real-time cybersecurity threat monitoring with MITRE ATT&CK classification, IoC extraction, and automated Excel reporting.

Built by [Rodrigo Moses](https://www.linkedin.com/in/rodrigo-m-793b36152/) · Python · tkinter · Open Source

---

## What it does

RMSecurity monitors **47 RSS feeds** from leading cybersecurity sources (Krebs on Security, BleepingComputer, CISA, Unit 42, Recorded Future, The Hacker News, and more), classifies every article using **MITRE ATT&CK** tactics, extracts **Indicators of Compromise**, and exports everything to a color-coded Excel report.

### Features

- **MITRE ATT&CK classification** — maps each article to a tactic (TA0001–TA0043) and technique (T1xxx)
- **Automatic severity scoring** — CRÍTICO / ALTO / MEDIO / BAJO based on keywords and CVSS score
- **IoC extraction** — CVEs, IP addresses (C2), MD5/SHA hashes, APT groups, victim organizations, affected countries, ransom amounts, data stolen, crypto wallets
- **50+ APT group detection** — Lazarus, Fancy Bear, Volt Typhoon, and more, with country-of-origin inference
- **Full article download** — fetches complete article text (not just RSS summaries) for deeper IoC extraction
- **Excel report with dashboard** — severity color-coding, category breakdown, executive summary sheet, clickable URLs
- **Optional Ollama integration** — connect a local LLM (llama3.2:3b) for semantic enrichment in Spanish
- **Dark cyberpunk UI** — neon-on-dark theme built with tkinter

### Feed categories

| Category | Examples |
|---|---|
| RANSOMWARE | LockBit, BlackCat, RansomHub activity |
| VULNERABILIDADES | CVEs, zero-days, patch releases |
| APT / ESPIONAJE | Nation-state campaigns |
| FILTRACIÓN DE DATOS | Breach reports, leak databases |
| MALWARE / TROYANOS | New malware families, RATs, stealers |
| INFRAESTRUCTURA CRÍTICA | ICS/SCADA, energy, water |
| PHISHING / INGENIERÍA SOCIAL | Campaigns, BEC, credential theft |
| CIBERCRIMEN / DARKWEB | Forums, marketplaces, threat actor chatter |

---

## Requirements

```
Python 3.9+
```

Install dependencies:

```bash
pip install feedparser requests openpyxl beautifulsoup4
```

Optional (for LLM enrichment):
```bash
# Install Ollama from https://ollama.com
ollama pull llama3.2:3b
```

---

## Usage

### Run directly

```bash
python cyber_intel_gui.py
```

Or double-click `INICIAR_CYBER_INTEL.bat` on Windows.

### Compile to EXE (Windows)

```bash
pip install pyinstaller
COMPILAR_CYBER.bat
```

The executable will appear in `EJECUTABLE\RMSecurity_CyberIntel.exe`.

---

## How it works

1. **Search** — enter keywords (e.g. `ransomware`, `APT`, `CVE-2024`) and click **BUSCAR**
2. **Results** — articles appear sorted by date, color-coded by severity and category
3. **Select & Export** — select articles and click **Exportar a Excel** to append to `THREAT_INTEL_IOC.xlsx`
4. **Dashboard** — the Excel file includes a `Resumen` sheet with counts by severity, category, and threat actor

### Pro tip
Leave it running in the background with a broad search (e.g. `cyber`) — it accumulates intelligence over time while you work on other tasks.

---

## Output — Excel columns

| Field | Description |
|---|---|
| Fecha | Publication date |
| Severidad | CRÍTICO / ALTO / MEDIO / BAJO |
| Categoría | Threat category |
| Táctica MITRE | ATT&CK tactic name |
| ID MITRE | TA00xx identifier |
| Técnicas T1 | T1xxx technique codes |
| CVSS | CVSS score if found |
| CVE | CVE identifiers |
| Actor / Grupo APT | Threat actor name |
| País Origen | Country of origin (inferred or explicit) |
| Víctima / Sector / País Víctima | Target details |
| Impacto | Impact summary |
| IPs C2 | Command & control IPs |
| Hashes | MD5 / SHA file hashes |
| Dominios Maliciosos | Malicious domains |
| Wallets Crypto | BTC / ETH / XMR wallets |
| URL | Link to original article |

---

## License

MIT — free to use, modify, and distribute.

---

*Built as an open-source Threat Intelligence project — contributions welcome.*
