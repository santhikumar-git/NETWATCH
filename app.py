
import streamlit as st
import requests
import socket
import ssl
import ipaddress
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from html.parser import HTMLParser

st.set_page_config(
    page_title="NETWATCH | Website Diagnostics",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background: #07111f;
    color: #e6f1ff;
}
h1, h2, h3 {
    color: #35d9ff !important;
}
[data-testid="stMetric"] {
    background: #101f33;
    padding: 16px;
    border-radius: 12px;
    border: 1px solid #193b55;
}
.stButton button {
    background: #00bfe8;
    color: #06111d;
    border-radius: 8px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)


class WebsiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.description = ""
        self.h1_count = 0
        self.images = 0
        self.images_without_alt = 0
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "title":
            self.in_title = True

        if tag == "meta":
            if attrs.get("name", "").lower() == "description":
                self.description = attrs.get("content", "")

        if tag == "h1":
            self.h1_count += 1

        if tag == "img":
            self.images += 1
            if not attrs.get("alt", "").strip():
                self.images_without_alt += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data.strip()


def validate_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url.startswith(("https://", "http://")):
        raise ValueError(
            "Enter a URL starting with https:// or http://"
        )

    parsed = urlparse(raw_url)

    if not parsed.hostname:
        raise ValueError("Invalid website address.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing login credentials are not allowed.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard web ports are allowed.")

    host = parsed.hostname.lower()

    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Local addresses are not allowed.")

    try:
        addresses = socket.getaddrinfo(
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Could not find the website address.")

    if not addresses:
        raise ValueError("No IP address found.")

    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if not ip.is_global:
            raise ValueError(
                "Private or non-public IP addresses are not allowed."
            )

    return parsed


def check_ssl(hostname):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443), timeout=5) as sock:
        with context.wrap_socket(
            sock, server_hostname=hostname
        ) as secure:
            certificate = secure.getpeercert()

            return {
                "status": "Valid certificate",
                "issuer": str(certificate.get("issuer", "Unknown")),
                "expires": certificate.get("notAfter", "Unknown")
            }


def scan_website(url):
    parsed = validate_url(url)
    hostname = parsed.hostname

    start = time.perf_counter()

    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False,
        stream=True,
        headers={
            "User-Agent": "NETWATCH-Educational-Diagnostics/1.0"
        }
    )

    elapsed = round(
        (time.perf_counter() - start) * 1000, 2
    )

    content = b""

    for chunk in response.iter_content(chunk_size=8192):
        content += chunk
        if len(content) > 1_000_000:
            break

    content_type = response.headers.get("Content-Type", "")
    html_text = ""

    if "text/html" in content_type.lower():
        html_text = content.decode(
            response.encoding or "utf-8",
            errors="replace"
        )

    parser = WebsiteParser()
    parser.feed(html_text)

    headers = response.headers

    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "Frame protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy"
    }

    header_results = {
        name: name in headers
        for name in security_headers
    }

    ssl_result = None

    if parsed.scheme == "https":
        try:
            ssl_result = check_ssl(hostname)
        except Exception as error:
            ssl_result = {"error": str(error)}

    score = 0
    score += 30 if response.status_code == 200 else 10
    score += 20 if parsed.scheme == "https" else 0
    score += (
        10 if ssl_result and "status" in ssl_result else 0
    )
    score += sum(header_results.values()) * 5
    score = min(score, 100)

    response.close()

    return {
        "website": url,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "status_code": response.status_code,
        "response_time_ms": elapsed,
        "content_type": content_type,
        "page_size_bytes": len(content),
        "security_headers": header_results,
        "ssl": ssl_result,
        "seo": {
            "title": parser.title,
            "description": parser.description,
            "h1_count": parser.h1_count,
            "images": parser.images,
            "images_without_alt": parser.images_without_alt
        },
        "health_score": score,
        "note": "Educational diagnostic score, not a security certification."
    }


with st.sidebar:
    st.title("🛡️ NETWATCH")
    st.caption("Website Diagnostics Platform")
    st.divider()
    st.write("MODULES")
    st.write("🌐 Website Scanner")
    st.write("🔒 SSL Analysis")
    st.write("🛡️ Security Headers")
    st.write("⚡ Performance")
    st.write("🔍 SEO Audit")
    st.write("📥 Reports")
    st.divider()
    st.caption("Version 3.0 | Educational Prototype")


st.title("🛡️ NETWATCH")
st.subheader("Advanced Website Diagnostics Dashboard")

st.write(
    "Analyze basic availability, HTTPS certificate, security headers, "
    "response time and SEO information of a public website."
)

st.info(
    "Use only public websites you own or have permission to assess. "
    "This tool performs basic, non-invasive checks."
)

url = st.text_input(
    "Enter website URL",
    placeholder="https://example.com"
)

scan_button = st.button(
    "🚀 START WEBSITE SCAN",
    use_container_width=True
)

if scan_button:
    if not url.strip():
        st.warning("Please enter a website URL.")

    else:
        try:
            with st.spinner("Analyzing website..."):
                report = scan_website(url)

            st.success("Website analysis completed!")

            st.divider()
            st.subheader("📊 Website Overview")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Health Score",
                f"{report['health_score']}/100"
            )

            col2.metric(
                "HTTP Status",
                report["status_code"]
            )

            col3.metric(
                "Response Time",
                f"{report['response_time_ms']} ms"
            )

            st.divider()
            st.subheader("🔒 SSL Certificate")

            if report["ssl"] and "status" in report["ssl"]:
                st.success(report["ssl"]["status"])
                st.write("Issuer:", report["ssl"]["issuer"])
                st.write("Expiry:", report["ssl"]["expires"])

            elif report["ssl"]:
                st.warning(
                    report["ssl"].get(
                        "error", "SSL check unavailable"
                    )
                )

            else:
                st.warning("HTTPS is not enabled.")

            st.divider()
            st.subheader("🛡️ Security Header Analysis")

            for name, present in report["security_headers"].items():
                if present:
                    st.success(f"✓ {name} detected")
                else:
                    st.warning(f"Not detected: {name}")

            st.caption(
                "Header presence alone does not prove that a website is secure."
            )

            st.divider()
            st.subheader("🔍 Basic SEO Analysis")

            seo = report["seo"]

            st.write(
                "**Page Title:**",
                seo["title"] or "Not found"
            )

            st.write(
                "**Meta Description:**",
                seo["description"] or "Not found"
            )

            st.write("**H1 Headings:**", seo["h1_count"])
            st.write("**Images:**", seo["images"])

            st.write(
                "**Images without ALT text:**",
                seo["images_without_alt"]
            )

            st.divider()
            st.subheader("⚡ Performance Information")

            st.write(
                "Response time:",
                report["response_time_ms"],
                "ms"
            )

            st.write(
                "Downloaded data:",
                report["page_size_bytes"],
                "bytes"
            )

            st.write("Content type:", report["content_type"])

            st.divider()
            st.subheader("📥 Download Report")

            report_json = json.dumps(report, indent=4)

            st.download_button(
                label="Download JSON Report",
                data=report_json,
                file_name="netwatch_report.json",
                mime="application/json"
            )

        except Exception as error:
            st.error(f"Scan could not be completed: {error}")


st.divider()

st.caption(
    "NETWATCH 3.0 | Educational website diagnostics | "
    "A health score is an estimate, not a security guarantee."
)
