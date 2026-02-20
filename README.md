#  OWASP Top 10 Security Agent
### Built with LangGraph + Google Gemini API

---

##  Installation

install from the requirements file:

```bash
pip install -r requirements.txt
```

---

** .env file:**
```bash
cp .env.example .env
# Edit .env and replace: GEMINI_API_KEY=your_actual_key_here
```

---

##  Run

```bash
python security_agent.py
```

Enter the target URL when prompted.
---

##  Project Structure

```
owasp_langgraph_gemini/
├── security_agent.py   ← Main agent (all code here)
├── requirements.txt    ← Dependencies
├── .env.example        ← API key template
└── README.md           ← This file
```

---

## Architecture

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

## Gemini Model Used

`gemini-2.0-flash` — fast, accurate, and free tier available.

we can change accordingly or other models can be used as openAI etc just change import and model type before invoke

