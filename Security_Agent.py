import ssl
import socket
from langgraph.graph import StateGraph, END, START
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage
from langchain_google_genai import ChatGoogleGenerativeAI

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
    Maps to: A01
    """
    base = state["url"].rstrip("/")
    findings = {}

    sensitive_paths = [
        "/login", "/config", "/configuration",
        "/.htaccess", "/backup", "/db",
        "/phpmyadmin", "/server-status", "/server-info",
        "/api/v1/users", "/api/users", "/robots.txt",
        "/sitemap.xml", "/swagger-ui.html", "/api-docs"
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

    # Linear: aggregator → report → done
    graph.add_edge("aggregator","report_generator")
    graph.add_edge("report_generator", END)

    return graph.compile()
