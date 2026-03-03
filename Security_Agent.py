import os
import json
import ssl
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import TypedDict, Annotated, List
from dotenv import load_dotenv
from colorama import Fore, Style, init

from langgraph.graph import StateGraph, END, START
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()
init(autoreset=True)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise EnvironmentError(
        "\nGEMINI_API_KEY not found!\n"
    )

class SecurityState(TypedDict):
    url: str
    messages: Annotated[list, add_messages]
  
    header_findings:  dict
    ssl_findings:     dict
    cookie_findings:  dict
    path_findings:    dict
    form_findings:    dict
    error_findings:   dict

    owasp_report:  dict
    risk_level:    str
    final_report:  str

    scan_complete: bool
    errors:        List[str]

def header_checker_node(state: SecurityState) -> dict:
    """
    Uses Gemini to evaluate HTTP response headers 
    for missing security policies and information disclosure.
    Maps to: A02, A03, A05, A06
    """
    url = state["url"]
    findings = {}

    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        actual_headers = dict(r.headers)

        llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",          
            google_api_key=GEMINI_API_KEY,
            temperature=0.1, 
        )

        prompt = f"""You are a security analyst evaluating HTTP response headers.
Target URL: {url}
Actual Headers Received: {json.dumps(actual_headers)}

Analyze these headers and identify:
1. Missing security headers (e.g., CSP, HSTS, frame options, etc.).
2. Information disclosure headers (e.g., Server, X-Powered-By, framework versions).

Respond ONLY with a valid JSON object in this exact format, with no markdown formatting:
{{
  "missing_headers": [
    {{"header": "Header-Name", "owasp": "AXX", "risk": "Why it matters"}}
  ],
  "disclosures": [
    {{"header": "Header-Name", "value": "Exposed Value", "owasp": "A06", "risk": "Why it matters"}}
  ]
}}
"""
        response = llm.invoke([HumanMessage(content=prompt)])
        clean_text = response.content.strip().lstrip("```json").rstrip("```").strip()
        analysis = json.loads(clean_text)

        for item in analysis.get("missing_headers", []):
            findings[item["header"]] = {
                "status": "FAIL",
                "owasp": item.get("owasp", "A05"),
                "risk": item.get("risk", "Missing security header")
            }
        
        for item in analysis.get("disclosures", []):
            findings[item["header"]] = {
                "status": "WARN",
                "owasp": item.get("owasp", "A06"),
                "value": item.get("value", ""),
                "risk": item.get("risk", "Technology exposed")
            }

    except requests.exceptions.RequestException as e:
        findings["connection_error"] = {"status": "ERROR", "message": str(e)}
    except json.JSONDecodeError:
        findings["llm_error"] = {"status": "ERROR", "message": "Failed to parse LLM header analysis."}

    return {
        "header_findings": findings,
        "messages": [AIMessage(content=f"[Header Checker] Done — dynamically analyzed headers")]
    }

def ssl_checker_node(state: SecurityState)->dict:
    url = state["url"]
    findings = {}
    if not url.startswith("https://"):
        findings["protocol"] = {"status": "FAIL", "owasp": "A02", "risk": "Site uses HTTP"}
        return {"ssl_findings": findings, "messages": [AIMessage(content="[SSL Checker] Done — site is on HTTP")]}
    
    hostname = urlparse(url).hostname
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        findings["protocol"] = {"status": "PASS", "value": "HTTPS enabled"}
        findings["certificate"] = {"status": "PASS", "expires": cert.get("notAfter", "Unknown")}
    except Exception as e:
        findings["error"] = {"status": "ERROR", "message": str(e)}

    return {"ssl_findings": findings, "messages": [AIMessage(content="[SSL Checker] Done")]}
    
def path_scanner_node(state: SecurityState) -> dict:
    parsed = urlparse(state["url"])
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings = {}

    # Extract tech stack from the header_checker that ran right before this!
    hf = state.get("header_findings", {})
    tech_stack = [f"{k}: {v.get('value')}" for k, v in hf.items() if v.get("status") == "WARN" and "value" in v]
    tech_context = f"The server exposed the following technology headers: {', '.join(tech_stack)}." if tech_stack else "No specific server technology headers were exposed."

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",          
        google_api_key=GEMINI_API_KEY,
        temperature=0.2, 
    )

    prompt = f"""You are an expert penetration tester. The target URL is: {base}
{tech_context}

Generate a list of the 20 most critical sensitive paths, files, or directories to check for exposure.
Tailor your guesses based on the identified tech stack and standard web application vulnerabilities.

Respond ONLY with a valid JSON array of strings. Do not include markdown formatting.
Example format: ["/admin", "/.env", "/api/swagger.json", "/server-status"]
"""
    
    # 1. Mandatory baseline paths (The Shotgun)
    baseline_paths = [
        "/.env", "/.git", "/robots.txt", "/sitemap.xml", 
        "/admin", "/server-status", "/backup.zip"
    ]

    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        clean_text = response.content.strip().lstrip("```json").rstrip("```").strip()
        ai_paths = json.loads(clean_text)
        
        if not isinstance(ai_paths, list):
            raise ValueError("LLM did not return a list.")
            
    except Exception as e:
        ai_paths = []

    # 2. Combine baseline + AI paths, remove duplicates, cap at 30 (The Sniper)
    combined_paths = list(set(baseline_paths + ai_paths))[:30]

    for path in combined_paths:
        try:
            r = requests.get(base + path, timeout=5, allow_redirects=False)

            if r.status_code == 200:
                findings[path] = {"status": "WARN", "owasp": "A01", "code": 200, "risk": "Publicly accessible"}
            elif r.status_code == 403:
                findings[path] = {"status": "INFO", "code": 403, "message": "Path forbidden"}
            elif r.status_code in (301, 302):
                findings[path] = {"status": "INFO", "code": r.status_code, "redirect": r.headers.get("Location", "unknown")}
            else:
                findings[path] = {"status": "PASS", "code": r.status_code}

        except requests.exceptions.Timeout:
            findings[path] = {"status": "TIMEOUT"}
        except Exception:
            findings[path] = {"status": "SKIP"}

    accessible = sum(1 for v in findings.values() if v.get("status") == "WARN")
    
    return {
        "path_findings": findings,
        "messages": [AIMessage(content=f"[Path Scanner] Done — {len(combined_paths)} context-aware paths checked, {accessible} accessible")]
    }
            
def cookie_checker_node(state: SecurityState) -> dict:
    """
    Inspects Set-Cookie attributes for security flags.
    Maps to: A07
    """
    url = state["url"]
    findings = {}

    try:
        r = requests.get(url, timeout=10)

        if not r.cookies:
            findings["_info"] = {
                "status":  "INFO",
                "message": "No cookies were set on the root endpoint"
            }
        else:
            for cookie in r.cookies:
                issues = []

                # HttpOnly — prevents JS from reading the cookie
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("Missing HttpOnly → XSS can steal this cookie")

                # Secure — only send cookie over HTTPS
                if not cookie.secure:
                    issues.append("Missing Secure flag → cookie sent over HTTP too")

                # SameSite — prevents cross-site request forgery
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("Missing SameSite → CSRF risk")

                findings[cookie.name] = {
                    "status": "FAIL" if issues else "PASS",
                    "owasp":  "A07",
                    "issues": issues
                }

    except Exception as e:
        findings["error"] = {"status": "ERROR", "message": str(e)}

    return {
        "cookie_findings": findings,
        "messages": [AIMessage(content=f"[Cookie Checker] Done — {len(findings)} cookie(s) analyzed")]
    }

def error_checker_node(state: SecurityState) -> dict:
    parsed = urlparse(state["url"])
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings = {}

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",          
        google_api_key=GEMINI_API_KEY,
        temperature=0.1, 
    )

    test_path = "/api/v1/internal_error_test_probe_xyz_999"
    
    try:
        r = requests.get(base + test_path, timeout=5)
        body_snippet = r.text[:2500] 

        prompt = f"""You are a security tool looking for Information Leakage.
I requested `{test_path}` on the server and received a {r.status_code} status.
Here is the first 2500 characters of the response body:

---
{body_snippet}
---

Does this response leak sensitive internal information? Look for stack traces, database errors, framework defaults, or internal paths.
Respond ONLY with a valid JSON object in this exact format (no markdown):
{{
  "leak_found": true/false,
  "leaked_details": ["detail 1", "detail 2"] 
}}
"""
        response = llm.invoke([HumanMessage(content=prompt)])
        clean_text = response.content.strip().lstrip("```json").rstrip("```").strip()
        analysis = json.loads(clean_text)

        findings[test_path] = {
            "status": "FAIL" if analysis.get("leak_found") else "PASS",
            "owasp": "A09",
            "status_code": r.status_code,
            "leaks_found": analysis.get("leaked_details", []),
            "risk": f"Error page reveals: {analysis.get('leaked_details')}" if analysis.get("leak_found") else None
        }

    except Exception as e:
        findings[test_path] = {"status": "ERROR", "message": str(e)}

    return {
        "error_findings": findings,
        "messages": [AIMessage(content="[Error Checker] Done — dynamic error content analyzed")]
    }
    
def form_sri_checker_node(state: SecurityState) -> dict:
    """
    Checks CSRF tokens on POST forms and SRI on external scripts.
    Maps to: A03, A04, A08
    """
    url = state["url"]
    findings = {}

    try:
        soup = BeautifulSoup(requests.get(url, timeout=10).text, "html.parser")

        #SRICheck (A08)
        ext_scripts  = [s for s in soup.find_all("script", src=True) if s["src"].startswith("http")]
        missing_sri  = [s["src"] for s in ext_scripts if not s.get("integrity")]

        findings["sri"] = {
            "status":  "FAIL" if missing_sri else "PASS",
            "owasp":   "A08",
            "missing": missing_sri[:4],
            "risk":    "CDN scripts loaded without integrity check" if missing_sri else None
        }

        #CSRF Check (A04)
        CSRF_NAMES = {"csrf_token", "_token", "csrf", "authenticity_token",
                      "_csrf", "csrfmiddlewaretoken", "verify_token"}

        csrf_issues = []
        for i, form in enumerate(soup.find_all("form")):
            if form.get("method", "GET").upper() != "POST":
                continue
            input_names = {inp.get("name", "").lower() for inp in form.find_all("input")}
            if not (input_names & CSRF_NAMES):
                csrf_issues.append(f"Form #{i+1} (action={form.get('action', '/')})")

        findings["csrf"] = {
            "status": "FAIL" if csrf_issues else "PASS",
            "owasp":  "A04",
            "issues": csrf_issues,
            "risk":   "POST forms missing CSRF tokens" if csrf_issues else None
        }

    except Exception as e:
        findings["error"] = {"status": "ERROR", "message": str(e)}

    return {
        "form_findings": findings,
        "messages": [AIMessage(content="[Form/SRI Checker] Done")]
    }

def aggregator_node(state: SecurityState) -> dict:
    """
    Combines results from all checker nodes into a single
    OWASP-mapped report and computes the risk level.
    """
    hf = state.get("header_findings", {})

    owasp_report = {
        "A01 - Broken Access Control": state.get("path_findings", {}),

        "A02 - Cryptographic Failures": state.get("ssl_findings", {}),

        "A03 - Injection (XSS)": {
            k: v for k, v in hf.items()
            if k == "Content-Security-Policy"
        },

        "A04 - Insecure Design": {
            "csrf": state.get("form_findings", {}).get("csrf", {})
        },

        "A05 - Security Misconfiguration": {
            k: v for k, v in hf.items()
            if k in ("X-Frame-Options", "X-Content-Type-Options",
                     "Referrer-Policy", "Permissions-Policy")
        },

        "A06 - Vulnerable Components": {
            k: v for k, v in hf.items()
            if k in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")
        },

        "A07 - Auth & Session Failures": state.get("cookie_findings", {}),

        "A08 - Software Integrity Failures": {
            "sri": state.get("form_findings", {}).get("sri", {})
        },

        "A09 - Logging & Monitoring Failures": state.get("error_findings", {}),

        "A10 - SSRF": {
            "_note": {
                "status":  "INFO",
                "message": "SSRF requires active payload testing — flagged for manual review.",
                "hint":    "Look for parameters named: url, redirect, next, dest, src, fetch, load"
            }
        }
    }

    #Risk Scoring 
    all_statuses = []
    for category_findings in owasp_report.values():
        for val in category_findings.values():
            if isinstance(val, dict):
                all_statuses.append(val.get("status", ""))

    fail_count = all_statuses.count("FAIL")
    warn_count = all_statuses.count("WARN")

    if fail_count >= 6:
        risk_level = "CRITICAL"
    elif fail_count >= 4:
        risk_level = "HIGH"
    elif fail_count >= 2 or warn_count >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "owasp_report": owasp_report,
        "risk_level":   risk_level,
        "messages": [AIMessage(
            content=f"[Aggregator] Done — Risk Level: {risk_level} "
                    f"({fail_count} failures, {warn_count} warnings)"
        )]
    }

def report_generator_node(state: SecurityState) -> dict:
    """
    Uses Google Gemini to generate a professional,
    human-readable security report from raw findings.
    """
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.0-flash",          
        google_api_key=GEMINI_API_KEY,
        temperature=0.1,             
        max_output_tokens=2048,
    )

    prompt = f"""You are a senior cybersecurity analyst. 
Generate a professional OWASP Top 10 security assessment report based on the automated scan results below.

Target URL : {state['url']}
Risk Level : {state['risk_level']}

{json.dumps(state['owasp_report'], indent=2)}

Structure your report exactly as follows:

1. EXECUTIVE SUMMARY
   - 3-4 sentences: overall security posture, risk level, most critical issues

2. FINDINGS BY OWASP CATEGORY
   - Only include categories that have FAIL or WARN status
   - For each: category name, what was found, why it matters

3. TOP 5 PRIORITIZED RECOMMENDATIONS
   - Ordered by severity (most critical first)
   - Each recommendation must be specific and actionable
   - Include the fix, not just the problem

4. DISCLAIMER
   - One short paragraph noting this is automated passive scanning only
   - Not a substitute for professional penetration testing

Keep the tone professional but clear. Avoid jargon where possible.
"""

    response = llm.invoke([HumanMessage(content=prompt)])

    return {
        "final_report":  response.content,
        "scan_complete": True,
        "messages": [AIMessage(content="[Report Generator] Done — Gemini report generated")]
    }


def build_security_graph():
    """
    Constructs the LangGraph with parallel checker nodes
    that all feed into aggregator → report generator.
    """
    graph = StateGraph(SecurityState)

    # Register nodes
    graph.add_node("header_checker",    header_checker_node)
    graph.add_node("ssl_checker",       ssl_checker_node)
    graph.add_node("cookie_checker",    cookie_checker_node)
    graph.add_node("path_scanner",      path_scanner_node)
    graph.add_node("form_sri_checker",  form_sri_checker_node)
    graph.add_node("error_checker",     error_checker_node)
    graph.add_node("aggregator",        aggregator_node)
    graph.add_node("report_generator",  report_generator_node)

    # Edges (Routing from START to checkers in parallel)
    graph.add_edge(START, "header_checker")
    graph.add_edge("header_checker", "path_scanner")
    graph.add_edge(START, "ssl_checker")
    graph.add_edge(START, "cookie_checker")
    graph.add_edge(START, "form_sri_checker")
    graph.add_edge(START, "error_checker")

    # Fan-in: All checkers converge at aggregator
    graph.add_edge("ssl_checker",      "aggregator")
    graph.add_edge("cookie_checker",   "aggregator")
    graph.add_edge("path_scanner",     "aggregator")
    graph.add_edge("form_sri_checker", "aggregator")
    graph.add_edge("error_checker",    "aggregator")

    # Final sequence
    graph.add_edge("aggregator", "report_generator")
    graph.add_edge("report_generator", END)

    return graph.compile()
    
def run_security_scan(url: str):
    """Entry point — runs the full OWASP assessment pipeline."""
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(Fore.CYAN  + "\n" + "=" * 60)
    print(Fore.CYAN  + "OWASP Top 10 Security Agent")
    print(Fore.CYAN  + "=" * 60)
    print(Fore.YELLOW + f"\nTarget  : {url}")
    print(Fore.YELLOW +  "Model   : gemini-2.0-flash")
    print(Fore.CYAN  + "\n" + "-" * 60 + "\n")

    graph = build_security_graph()

    initial_state: SecurityState = {
        "url":             url,
        "messages":        [HumanMessage(content=f"Perform OWASP Top 10 scan on {url}")],
        "header_findings": {},
        "ssl_findings":    {},
        "cookie_findings": {},
        "path_findings":   {},
        "form_findings":   {},
        "error_findings":  {},
        "owasp_report":    {},
        "risk_level":      "",
        "final_report":    "",
        "scan_complete":   False,
        "errors":          [],
    }

    print(Fore.GREEN + "Running checks...\n")

    # We use invoke() here. It will run the entire graph sequentially and guarantee no data is lost at the end.
    final_state = graph.invoke(initial_state)

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.GREEN + "FINAL SECURITY REPORT")
    print(Fore.CYAN + "=" * 60 + "\n")
    print(final_state.get("final_report", "Report generation failed."))

    print(Fore.CYAN + "\n" + "=" * 60)
  
    print(Fore.YELLOW + f"   Overall Risk Level : {final_state.get('risk_level', 'UNKNOWN')}")
    print(Fore.CYAN  + "=" * 60 + "\n")

    return final_state


if __name__ == "__main__":
    print(Fore.CYAN + "\nOWASP Top 10 AI Security Agent — LangGraph + Gemini\n")
    url = input(Fore.WHITE + "Enter target URL: ").strip()
    if not url:
        print(Fore.RED + "No URL provided. Exiting.")
    else:
        run_security_scan(url)
