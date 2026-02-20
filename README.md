# 🔐 OWASP Top 10 Security Agent
### Built with LangGraph + Google Gemini API

---

## 📦 Installation

Run this single command to install everything:

```bash
pip install langgraph langchain langchain-core langchain-google-genai \
            google-generativeai requests beautifulsoup4 colorama python-dotenv
```

Or install from the requirements file:

```bash
pip install -r requirements.txt
```

---

## 🔑 Setup — Gemini API Key

1. Go to **https://aistudio.google.com/app/apikey**
2. Create a new API key (it's free)
3. Set it up using **one** of these methods:

**Option A — .env file (recommended):**
```bash
cp .env.example .env
# Edit .env and replace: GEMINI_API_KEY=your_actual_key_here
```

**Option B — environment variable:**
```bash
# Linux / Mac
export GEMINI_API_KEY=your_key_here

# Windows (Command Prompt)
set GEMINI_API_KEY=your_key_here

# Windows (PowerShell)
$env:GEMINI_API_KEY="your_key_here"
```

---

## 🚀 Run

```bash
python security_agent.py
```

Enter the target URL when prompted.

---

## 🎯 Safe Practice Targets

> ⚠️ Only scan websites you own or have explicit permission to test.

These are intentionally vulnerable apps you can safely test on:

```
http://testphp.vulnweb.com          ← Public test site by Acunetix
http://zero.webappsecurity.com      ← Public test site

# Local (Docker required):
docker run -p 80:80 vulnerables/web-dvwa     ← DVWA
docker run -p 8080:8080 webgoat/webgoat      ← WebGoat
```

---

## 🗂️ Project Structure

```
owasp_langgraph_gemini/
├── security_agent.py   ← Main agent (all code here)
├── requirements.txt    ← Dependencies
├── .env.example        ← API key template
└── README.md           ← This file
```

---

## 🏗️ Architecture

```
         START
           │
    ┌──────┴───────────────────────────────────┐
    │      │         │         │       │       │
Header   SSL     Cookie    Path    Form/SRI  Error
Checker Checker Checker  Scanner  Checker  Checker
    │      │         │         │       │       │
    └──────┴─────────┴─────────┴───────┴───────┘
                          │
                     Aggregator
                    (OWASP mapping
                    + risk scoring)
                          │
                  Report Generator
                  (Gemini AI writes
                   the final report)
                          │
                         END
```

---

## 📋 What Gets Checked

| OWASP | Check | Method |
|-------|-------|--------|
| A01 | Exposed admin/sensitive paths | HTTP status codes |
| A02 | HTTPS + SSL certificate validity | SSL handshake |
| A03 | Content-Security-Policy header | Response headers |
| A04 | CSRF tokens on POST forms | HTML parsing |
| A05 | Security headers (X-Frame, etc.) | Response headers |
| A06 | Version disclosure in headers | Response headers |
| A07 | Cookie flags (HttpOnly, Secure, SameSite) | Cookie inspection |
| A08 | Subresource Integrity on CDN scripts | HTML parsing |
| A09 | Stack traces in error pages | Content analysis |
| A10 | SSRF indicators | Manual review flagged |

---

## 🤖 Gemini Model Used

`gemini-2.0-flash` — fast, accurate, and free tier available.

To switch models, edit line in `security_agent.py`:
```python
model="gemini-2.0-flash"       # default (fast)
model="gemini-1.5-pro"         # more powerful
model="gemini-2.0-flash-lite"  # most lightweight
```

---

## ⚠️ Legal Disclaimer

This tool performs **passive, non-destructive** checks only. No exploits are run.
Always obtain written permission before scanning any website you do not own.
This is not a substitute for professional penetration testing.
