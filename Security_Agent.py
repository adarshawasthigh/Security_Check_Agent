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
    Checks HTTP response headers.
    Maps to: A02, A03, A05, A06
    """
    url = state["url"]
    findings = {}

    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        hdrs = r.headers
        expected = {
            "Strict-Transport-Security": ("A02", "Missing HSTS — browser won't force HTTPS"),
            "Content-Security-Policy":   ("A03", "No CSP — XSS attacks can execute freely"),
            "X-Frame-Options":           ("A05", "No clickjacking protection"),
            "X-Content-Type-Options":    ("A05", "MIME-type sniffing allowed"),
            "Referrer-Policy":           ("A05", "Referrer URL leakage possible"),
            "Permissions-Policy":        ("A05", "Browser API access unrestricted"),
        }

        for header, (owasp, risk) in expected.items():
            if header in hdrs:
                findings[header] = {
                    "status": "PASS",
                    "value": hdrs[header]
                }
            else:
                findings[header] = {
                    "status": "FAIL",
                    "owasp": owasp,
                    "risk":  risk
                }

        # Headers that should NOT be present (version disclosure)
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
        for h in disclosure_headers:
            if h in hdrs:
                findings[h] = {
                    "status": "WARN",
                    "owasp":  "A06",
                    "value":  hdrs[h],
                    "risk":   f"Technology version exposed: {hdrs[h]}"
                }

    except requests.exceptions.RequestException as e:
        findings["connection_error"] = {"status": "ERROR", "message": str(e)}

    return {
        "header_findings": findings,
        "messages": [AIMessage(content=f"[Header Checker] Done — {len(findings)} items checked")]
    }

def ssl_checker_node(state: SecurityState)->dict:
    """
    Verifies HTTPS usage and SSL certificate validity.
    Maps to: A02
    """
    url = state["url"]
    findings = {}

    #HTTP check
    if not url.startswith("https://"):
        findings["protocol"] = {
            "status": "FAIL",
            "owasp":  "A02",
            "risk":   "Site uses HTTP — all data transmitted in plaintext"
        }
        return {
            "ssl_findings": findings,
            "messages": [AIMessage(content="[SSL Checker] Done — site is on HTTP (no TLS)")]
        }
    # validate ssl certificate
    hostname = urlparse(url).hostname
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        findings["protocol"]    = {"status": "PASS", "value": "HTTPS enabled"}
        findings["certificate"] = {
            "status":  "PASS",
            "expires": cert.get("notAfter", "Unknown"),
            "subject": str(cert.get("subject", ""))
        }

    except ssl.SSLCertVerificationError as e:
        findings["certificate"] = {
            "status": "FAIL",
            "owasp":  "A02",
            "risk":   f"Certificate verification failed: {str(e)}"
        }
    except ssl.SSLError as e:
        findings["ssl_error"] = {
            "status": "FAIL",
            "owasp":  "A02",
            "risk":   f"SSL handshake error: {str(e)}"
        }
    except Exception as e:
        findings["error"] = {"status": "ERROR", "message": str(e)}

    return {
        "ssl_findings": findings,
        "messages": [AIMessage(content="[SSL Checker] Done — certificate and protocol checked")]
    }

def path_scanner_node(state: SecurityState) -> dict:
    """
    Probes commonly known sensitive URLs.
    Maps to: A01,A05
    """
    base = state["url"].rstrip("/")
    findings = {}

    sensitive_paths = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php",
        "/login", "/dashboard", "/config", "/configuration",
        "/.env", "/.git", "/.htaccess", "/backup", "/db",
        "/phpmyadmin", "/server-status", "/server-info",
        "/api/v1/users", "/api/users", "/robots.txt",
        "/sitemap.xml", "/actuator", "/actuator/env",
        "/console", "/swagger-ui.html", "/api-docs"
    ]
    for path in sensitive_paths:
        try:
            r = requests.get(base + path,timeout=5, allow_redirects=False)

            if r.status_code == 200:
                findings[path] = {
                    "status": "WARN",
                    "owasp":  "A01",
                    "code":   200,
                    "risk":   "Publicly accessible — verify authentication is required"
                }
            elif r.status_code == 403:
                findings[path] = {
                    "status":  "INFO",
                    "code":    403,
                    "message": "Path exists but access is forbidden"
                }
            elif r.status_code in (301, 302):
                findings[path] = {
                    "status":   "INFO",
                    "code":     r.status_code,
                    "redirect": r.headers.get("Location", "unknown")
                }
            else:
                findings[path] = {"status": "PASS", "code": r.status_code}

        except requests.exceptions.Timeout:
            findings[path] = {"status": "TIMEOUT"}
        except Exception:
            findings[path] = {"status": "SKIP"}

    accessible = sum(1 for v in findings.values() if v.get("status") == "WARN")
    return {
        "path_findings": findings,
        "messages": [AIMessage(
            content=f"[Path Scanner] Done — {len(sensitive_paths)} paths checked, "
                    f"{accessible} accessible"
        )]
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
    """
    Checks if error pages leak stack traces or internal details.
    Maps to: A09
    """
    base = state["url"].rstrip("/")
    findings = {}

    test_paths = [
        "/this-page-absolutely-does-not-exist-xyz-123",
        "/error-test-probe-abc"
    ]
    leak_keywords = [
        "stack trace", "traceback", "exception",
        "sql syntax", "at line", "debug", "undefined method",
        "mysql_fetch", "ORA-", "pg_query", "mysqli_error",
        "fatal error", "parse error", "notice:", "warning:",
        "internal server error details", "django.core",
        "werkzeug", "flask", "laravel", "symfony"
    ]

    for path in test_paths:
        try:
            r = requests.get(base + path, timeout=5)
            body = r.text.lower()
            found_leaks = [k for k in leak_keywords if k in body]

            findings[path] = {
                "status":      "FAIL" if found_leaks else "PASS",
                "owasp":       "A09",
                "status_code": r.status_code,
                "leaks_found": found_leaks,
                "risk":        f"Error page reveals internal details: {found_leaks}"
                               if found_leaks else None
            }
        except Exception as e:
            findings[path] = {"status": "ERROR", "message": str(e)}

    return {
        "error_findings": findings,
        "messages": [AIMessage(content="[Error Checker] Done — error page content analyzed")]
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

    # nodes
    graph.add_node("header_checker",    header_checker_node)
    graph.add_node("ssl_checker",       ssl_checker_node)
    graph.add_node("cookie_checker",    cookie_checker_node)
    graph.add_node("path_scanner",      path_scanner_node)
    graph.add_node("form_sri_checker",  form_sri_checker_node)
    graph.add_node("error_checker",     error_checker_node)
    graph.add_node("aggregator",        aggregator_node)
    graph.add_node("report_generator",  report_generator_node)

    #edges(Routing)
    graph.add_edge(START, "header_checker")
    graph.add_edge(START, "ssl_checker")
    graph.add_edge(START, "cookie_checker")
    graph.add_edge(START, "path_scanner")
    graph.add_edge(START, "form_sri_checker")
    graph.add_edge(START, "error_checker")

    graph.add_edge("header_checker",   "aggregator")
    graph.add_edge("ssl_checker",      "aggregator")
    graph.add_edge("cookie_checker",   "aggregator")
    graph.add_edge("path_scanner",     "aggregator")
    graph.add_edge("form_sri_checker", "aggregator")
    graph.add_edge("error_checker",    "aggregator")

    graph.add_edge("aggregator","report_generator")
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

    for event in graph.stream(initial_state):
        for node_name, node_output in event.items():
            if "messages" in node_output:
                for msg in node_output["messages"]:
                    if isinstance(msg, AIMessage):
                        print(Fore.WHITE + f"   {msg.content}")
                        
    final_state = graph.invoke(initial_state)

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.GREEN + "FINAL SECURITY REPORT")
    print(Fore.CYAN + "=" * 60 + "\n")
    print(final_state["final_report"])

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.YELLOW + f"   Overall Risk Level : {final_state['risk_level']}")
    print(Fore.CYAN  + "=" * 60 + "\n")

    return final_state

if __name__ == "__main__":
    print(Fore.CYAN + "\nOWASP Top 10 AI Security Agent — LangGraph + Gemini\n")
    url = input(Fore.WHITE + "Enter target URL: ").strip()
    if not url:
        print(Fore.RED + "No URL provided. Exiting.")
    else:
        run_security_scan(url)
