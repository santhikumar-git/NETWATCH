cat > app.py <<'PY'
import streamlit as st
import requests
import socket
import ssl
import ipaddress
import time
import re
import json
from urllib.parse import urlparse
from html.parser import HTMLParser
from datetime import datetime, timezone

st.set_page_config(
    page_title="NETWATCH 3.0",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background: #07111f;
    color: #e7f1ff;
}
[data-testid="stMetric"] {
    background: #101f33;
    border: 1px solid #1b4260;
    padding: 15px;
    border-radius: 12px;
}
div.stButton > button {
    background: linear-gradient(90deg,#0877c9,#00b8bd);
    color: white;
    border: 0;
    border-radius: 9px;
    font-weight: bold;
}
h1, h2, h3 {
    color: #55cfff !important;
}
</style>
""", unsafe_allow_html=True)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.in_title = False
        self.description = ""
        self.h1_count = 0
        self.images = 0
        self.missing_alt = 0
        self.links = 0

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)

        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            if data.get("name", "").lower() == "description":
                self.description = data.get("content", "")
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "img":
            self.images += 1
            if not data.get("alt", "").strip():
                self.missing_alt += 1
        elif tag == "a" and data.get("href"):
            self.links += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def validate_website(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Enter a website address.")

    if not re.match(r"^https?://", raw_url, re.I):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid website address.")

    if parsed.username or parsed.password:
        raise ValueError("Do not include login credentials in the URL.")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid port number.")

    if port is not None and port not in (80, 443):
        raise ValueError("Only standard web ports are supported.")

    host = parsed.hostname.rstrip(".").lower()

    if host == "localhost" or host.endswith(
        (".local", ".internal", ".test")
    ):
        raise ValueError("Local and internal hostnames are not allowed.")

    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
            addresses = sorted(set(
                record[4][0] for record in records
            ))
        except socket.gaierror:
            raise ValueError("DNS lookup failed.")

    if not addresses:
        raise ValueError("No IP addresses found.")

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Private or reserved IP addresses are not allowed.")

    return raw_url, host, addresses


def get_ssl_info(host):
    context = ssl.create_default_context()

    with socket.create_connection((host, 443), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure_sock:
            cert = secure_sock.getpeercert()

            expiry = datetime.strptime(
                cert["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            days_left = (
                expiry - datetime.now(timezone.utc)
            ).days

            return {
                "valid": True,
                "expiry": expiry.strftime("%Y-%m-%d"),
                "days_left": days_left
            }


def fetch_website(url):
    start = time.perf_counter()

    response = requests.get(
        url,
        timeout=(5, 10),
        allow_redirects=False,
        stream=True,
        verify=True,
        headers={
            "User-Agent": "NETWATCH-Educational-Monitor/3.0"
        }
    )

    body = bytearray()

    try:
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue

            remaining = 1_000_000 - len(body)
            body.extend(chunk[:remaining])

            if len(body) >= 1_000_000:
                break

        elapsed = round(
            (time.perf_counter() - start) * 1000, 2
        )

        html = bytes(body).decode(
            response.encoding or "utf-8",
            errors="replace"
        )

        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "html": html,
            "bytes": len(body),
            "time": elapsed,
            "content_type": response.headers.get("Content-Type", ""),
            "redirect": response.headers.get("Location")
        }
    finally:
        response.close()


def analyse_security(headers, is_https):
    checks = {
        "HTTPS": is_https,
        "HSTS": bool(headers.get("Strict-Transport-Security")) if is_https else False,
        "Content Security Policy": bool(headers.get("Content-Security-Policy")),
        "X-Content-Type-Options": (
            headers.get("X-Content-Type-Options", "").lower() == "nosniff"
        ),
        "Frame protection": bool(
            headers.get("X-Frame-Options")
            or "frame-ancestors" in headers.get(
                "Content-Security-Policy", ""
            ).lower()
        ),
        "Referrer Policy": bool(headers.get("Referrer-Policy")),
        "Permissions Policy": bool(headers.get("Permissions-Policy"))
    }

    cookie = headers.get("Set-Cookie", "").lower()

    if cookie:
        checks["Cookie Secure attribute"] = "secure" in cookie
        checks["Cookie HttpOnly attribute"] = "httponly" in cookie
        checks["Cookie SameSite attribute"] = "samesite" in cookie

    return checks


def run_scan(raw_url):
    url, host, addresses = validate_website(raw_url)

    result = {
        "website": url,
        "domain": host,
        "ip_addresses": addresses,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "issues": [],
        "recommendations": []
    }

    is_https = url.startswith("https://")
    result["https"] = is_https

    if is_https:
        try:
            result["ssl"] = get_ssl_info(host)
        except (OSError, ssl.SSLError, KeyError, ValueError):
            result["ssl"] = None
            result["issues"].append(
                "SSL certificate could not be verified."
            )
    else:
        result["ssl"] = None
        result["issues"].append("Website does not use HTTPS.")

    page = fetch_website(url)
    result["page"] = page

    result["availability"] = 200 <= page["status"] < 400

    if not result["availability"]:
        result["issues"].append(
            f"Website returned HTTP {page['status']}."
        )

    if page["status"] in (301, 302, 303, 307, 308):
        result["recommendations"].append(
            "A redirect was detected. Its destination was not followed."
        )

    result["security"] = analyse_security(
        page["headers"], is_https
    )

    parser = PageParser()
    parser.feed(page["html"])

    result["seo"] = {
        "title": parser.title.strip(),
        "description": parser.description.strip(),
        "h1_count": parser.h1_count,
        "images": parser.images,
        "images_missing_alt": parser.missing_alt,
        "links": parser.links
    }

    if not parser.title.strip():
        result["issues"].append("HTML title is missing.")

    if not parser.description.strip():
        result["recommendations"].append(
            "Consider adding a meta description."
        )

    if parser.missing_alt:
        result["recommendations"].append(
            f"{parser.missing_alt} images lack alternative text."
        )

    if parser.h1_count == 0:
        result["recommendations"].append(
            "Consider adding a main H1 heading."
        )

    if page["time"] > 2000:
        result["recommendations"].append(
            "Response time exceeded 2 seconds in this check."
        )

    if page["bytes"] >= 1_000_000:
        result["recommendations"].append(
            "HTML analysis was limited to the first 1 MB."
        )

    passed = sum(result["security"].values())
    total = len(result["security"])

    score = 100

    if not result["availability"]:
        score -= 35

    if not is_https:
        score -= 20

    if is_https and result["ssl"] is None:
        score -= 15

    if result["ssl"] and result["ssl"]["days_left"] < 30:
        score -= 10

    score -= min(25, (total - passed) * 4)

    if page["time"] > 2000:
        score -= 10

    if not parser.title.strip():
        score -= 5

    result["health_score"] = max(0, min(100, score))
    result["security_passed"] = passed
    result["security_total"] = total

    return result


# SIDEBAR
with st.sidebar:
    st.title("🛡️ NETWATCH")
    st.caption("CYBER INTELLIGENCE PLATFORM")
    st.divider()
    section = st.radio(
        "NAVIGATION",
        [
            "Overview",
            "Website Scanner",
            "Security Analysis",
            "Performance",
            "SEO Audit",
            "Reports"
        ]
    )
    st.divider()
    st.caption("VERSION 3.0")
    st.caption("Educational diagnostic tool")


# HEADER
st.title("🛡️ NETWATCH")
st.markdown("### ADVANCED WEBSITE DIAGNOSTICS")
st.caption(
    "WEBSITE HEALTH  •  SECURITY CONFIGURATION  •  PERFORMANCE  •  SEO"
)

st.info(
    "Only assess public websites you own or have permission to check. "
    "NETWATCH performs limited, non-invasive checks. It is not a "
    "penetration-testing tool or a guarantee of security."
)


# SCANNER
if section in ("Overview", "Website Scanner"):

    st.subheader("🌐 Website Scanner")

    website = st.text_input(
        "Enter website address",
        placeholder="https://example.com"
    )

    if st.button("🚀 START WEBSITE ANALYSIS", type="primary"):

        try:
            with st.spinner("Analysing website..."):
                st.session_state["report"] = run_scan(website)

        except requests.exceptions.SSLError:
            st.error("HTTPS certificate verification failed.")

        except requests.exceptions.Timeout:
            st.error("Website request timed out.")

        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the website.")

        except (ValueError, requests.exceptions.RequestException) as error:
            st.error(str(error))

        except Exception:
            st.error("Unexpected error. Please check the website address.")


# RESULTS
if "report" in st.session_state:

    r = st.session_state["report"]
    page = r["page"]
    seo = r["seo"]

    if section in ("Overview", "Website Scanner"):

        st.divider()
        st.subheader("📊 Website Health Overview")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Health Index", f"{r['health_score']}/100")
        c2.metric("HTTP Status", page["status"])
        c3.metric("Response Time", f"{page['time']} ms")
        c4.metric("IP Addresses", len(r["ip_addresses"]))

        st.progress(r["health_score"] / 100)

        if r["health_score"] >= 80:
            st.success("Good diagnostic score.")
        elif r["health_score"] >= 50:
            st.warning("Some configuration improvements are recommended.")
        else:
            st.error("Several diagnostic issues were identified.")

        st.write("**Website:**", r["website"])
        st.write("**Domain:**", r["domain"])
        st.write("**IP addresses:**", ", ".join(r["ip_addresses"]))
        st.write("**HTTPS:**", "Enabled" if r["https"] else "Not enabled")

        if r["ssl"]:
            st.write("**Certificate expiry:**", r["ssl"]["expiry"])
            st.write("**Days remaining:**", r["ssl"]["days_left"])

        st.write("**Measured response content:**", f"{page['bytes']:,} bytes")

        if r["issues"]:
            st.subheader("⚠️ Findings")
            for item in r["issues"]:
                st.warning(item)

        if r["recommendations"]:
            st.subheader("💡 Recommendations")
            for item in r["recommendations"]:
                st.info(item)

        if not r["issues"] and not r["recommendations"]:
            st.success("No findings were identified by these basic checks.")

    if section == "Security Analysis":

        st.subheader("🔐 Security Configuration")

        for name, passed in r["security"].items():
            if passed:
                st.success(f"✓ {name}: Detected")
            else:
                st.warning(f"△ {name}: Not detected or not applicable")

        st.caption(
            "A missing header is a configuration observation, "
            "not proof that a website is vulnerable."
        )

    if section == "Performance":

        st.subheader("⚡ Performance Analysis")

        c1, c2 = st.columns(2)
        c1.metric("Response time", f"{page['time']} ms")
        c2.metric("Downloaded HTML", f"{page['bytes']:,} bytes")

        st.write("**HTTP content type:**", page["content_type"])

        st.caption(
            "This is a single request measurement, not a full "
            "Core Web Vitals or load-test result."
        )

    if section == "SEO Audit":

        st.subheader("🔎 Basic SEO Analysis")

        st.write("**Page title:**", seo["title"] or "Not found")
        st.write("**Meta description:**", seo["description"] or "Not found")
        st.metric("H1 headings", seo["h1_count"])
        st.metric("Images", seo["images"])
        st.metric("Images missing alt text", seo["images_missing_alt"])
        st.metric("Links found", seo["links"])

        st.caption(
            "This is a limited HTML-based SEO review, not a complete SEO audit."
        )

    if section == "Reports":

        st.subheader("📄 Diagnostic Report")

        report_copy = {
            "website": r["website"],
            "domain": r["domain"],
            "checked_at": r["checked_at"],
            "health_score": r["health_score"],
            "availability": r["availability"],
            "http_status": page["status"],
            "response_time_ms": page["time"],
            "ip_addresses": r["ip_addresses"],
            "https": r["https"],
            "ssl": r["ssl"],
            "security_checks": r["security"],
            "seo": seo,
            "issues": r["issues"],
            "recommendations": r["recommendations"]
        }

        st.json(report_copy)

        st.download_button(
            "⬇️ DOWNLOAD JSON REPORT",
            data=json.dumps(report_copy, indent=4),
            file_name="netwatch_report.json",
            mime="application/json"
        )

else:
    if section != "Website Scanner":
        st.info("Run a website scan to view diagnostic results here.")


st.divider()
st.caption(
    "NETWATCH 3.0 | Educational Website Diagnostics | "
    "Results represent a limited check at the time of scanning."
)
PY
