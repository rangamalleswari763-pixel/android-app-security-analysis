from pathlib import Path
from collections import Counter
import csv
import datetime as dt
import html
import re
import struct
import socket

ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "logs"
RESULTS = ROOT / "results"
CAPTURES = ROOT / "captures"
REPORTS = ROOT / "reports"
REPORTS.mkdir(parents=True, exist_ok=True)

FRIDA_FILE = LOGS / "frida_runtime_output.txt"
LOGCAT_FILE = LOGS / "diva_dynamic_logcat.txt"
PCAP_FILE = CAPTURES / "diva_final_test.pcap"
HIERARCHY_FILE = RESULTS / "network_analysis.csv"
PACKET_FILE = RESULTS / "network_packet_details.csv"

OUTPUT = REPORTS / "diva_dynamic_analysis_dashboard.html"
PACKAGE = "jakhar.aseem.diva"



def read_text(path):
    if not path.exists():
        return ""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in raw[:200]:
        for enc in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                return raw.decode(enc, errors="replace")
            except (UnicodeError, LookupError):
                pass
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except (UnicodeError, LookupError):
            pass
    return raw.decode("utf-8", errors="replace")


def read_csv(path):
    if not path.exists():
        return []
    for enc in ("utf-8-sig", "utf-16", "utf-8", "latin-1"):
        try:
            with path.open("r", encoding=enc, newline="") as handle:
                return list(csv.DictReader(handle))
        except (UnicodeError, csv.Error, OSError):
            continue
    return []


def safe(value):
    return html.escape(str(value if value is not None else ""))


def mask_test_numbers(message):
    """Mask long numeric strings in displayed log text."""
    return re.sub(r"\b\d{4,}\b", "[test value masked]", str(message))




# ---------------------------- FRIDA / LOGCAT ----------------------------

frida_text = read_text(FRIDA_FILE)
logcat_text = read_text(LOGCAT_FILE)

frida_attached = bool(re.search(r"attached to\s+DIVA", frida_text, re.I))
frida_hooked = bool(re.search(r"android\.util\.Log\.e\(\)\s+hook installed", frida_text, re.I))
frida_messages = re.findall(r"\[LOG\.e\]\s*Message:\s*(.*)", frida_text)
frida_tags = re.findall(r"\[LOG\.e\]\s*Tag:\s*(.*)", frida_text)

logcat_pattern = re.compile(
    r"(?P<time>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"
    r".*?E/diva-log\s*\(\s*(?P<pid>\d+)\s*\):\s*(?P<message>.*)"
)
logcat_events = []
for line in logcat_text.splitlines():
    match = logcat_pattern.search(line)
    if match:
        logcat_events.append({
            "time": match.group("time"),
            "pid": match.group("pid"),
            "message": match.group("message").strip()
        })


# ---------------------------- PCAP PARSER ----------------------------
# Lightweight classic-PCAP parser. It does not assign traffic to DIVA.

def parse_pcap(path):
    data = {
        "frames": 0, "bytes": 0, "start": None, "end": None,
        "error": "", "dns": [], "http": [], "tls_names": []
    }
    if not path.exists():
        data["error"] = "PCAP file not found"
        return data

    raw = path.read_bytes()
    if len(raw) < 24:
        data["error"] = "PCAP file is incomplete"
        return data

    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if raw[:4] not in formats:
        data["error"] = "Unsupported PCAP format"
        return data

    endian, scale = formats[raw[:4]]
    try:
        _, major, minor, _, _, _, linktype = struct.unpack(endian + "IHHIIII", raw[:24])
    except struct.error:
        data["error"] = "Invalid PCAP header"
        return data
    if linktype != 1:
        data["error"] = f"Unsupported link type {linktype}; Ethernet expected"
        return data

    offset = 24
    while offset + 16 <= len(raw):
        sec, frac, included, original = struct.unpack(endian + "IIII", raw[offset:offset + 16])
        offset += 16
        frame = raw[offset:offset + included]
        offset += included
        if len(frame) < 14:
            continue

        stamp = sec + frac / scale
        data["frames"] += 1
        data["bytes"] += original
        data["start"] = stamp if data["start"] is None else data["start"]
        data["end"] = stamp

        ethertype = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]
        if ethertype == 0x0800 and len(payload) >= 20:
            ihl = (payload[0] & 15) * 4
            if ihl < 20 or len(payload) < ihl:
                continue
            proto = payload[9]
            src = socket.inet_ntoa(payload[12:16])
            dst = socket.inet_ntoa(payload[16:20])
            transport = payload[ihl:]
        elif ethertype == 0x86DD and len(payload) >= 40:
            src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
            proto = payload[6]
            transport = payload[40:]
        else:
            continue

        if proto == 17 and len(transport) >= 8:
            sport, dport = struct.unpack("!HH", transport[:4])
            app = transport[8:]
            if (sport == 53 or dport == 53) and len(app) >= 17:
                labels, pos = [], 12
                try:
                    while pos < len(app) and app[pos] != 0:
                        length = app[pos]
                        if length & 0xC0:
                            break
                        pos += 1
                        labels.append(app[pos:pos + length].decode("ascii", "ignore"))
                        pos += length
                    if labels:
                        data["dns"].append(".".join(labels))
                except Exception:
                    pass

        elif proto == 6 and len(transport) >= 20:
            tcp_len = ((transport[12] >> 4) & 15) * 4
            app = transport[tcp_len:] if tcp_len <= len(transport) else b""
            if app:
                decoded = app.decode("latin-1", errors="ignore")
                request = re.match(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+(\S+)", decoded)
                if request:
                    host = re.search(r"(?im)^Host:\s*(.+?)\s*$", decoded)
                    data["http"].append({
                        "method": request.group(1),
                        "uri": request.group(2),
                        "host": host.group(1).strip() if host else "",
                        "source": src,
                        "destination": dst
                    })
                if app.startswith(b"\x16"):
                    for name in re.findall(rb"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", app):
                        text_name = name.decode("ascii", "ignore")
                        if text_name not in data["tls_names"]:
                            data["tls_names"].append(text_name)
    return data


pcap = parse_pcap(PCAP_FILE)
hierarchy_rows = read_csv(HIERARCHY_FILE)
packet_rows = read_csv(PACKET_FILE)

hierarchy = {}
for row in hierarchy_rows:
    key = (row.get("hierarchy_path") or "").strip().lower()
    try:
        hierarchy[key] = int(row.get("frames") or 0)
    except ValueError:
        continue

# Leaf-level protocol categories only; nested parent counts are not added.
tcp_total = hierarchy.get("frame > eth > ip > tcp", 0)
http_frames = hierarchy.get("frame > eth > ip > tcp > http", 0)
tls_frames = hierarchy.get("frame > eth > ip > tcp > tls", 0)
protocols = [
    ("IPv6 ICMPv6", hierarchy.get("frame > eth > ipv6 > icmpv6", 0)),
    ("IPv6 UDP mDNS", hierarchy.get("frame > eth > ipv6 > udp > mdns", 0)),
    ("IPv4 IGMP", hierarchy.get("frame > eth > ip > igmp", 0)),
    ("IPv4 TCP other", max(tcp_total - http_frames - tls_frames, 0)),
    ("HTTP", http_frames),
    ("TLS", tls_frames),
    ("IPv4 UDP DNS", hierarchy.get("frame > eth > ip > udp > dns", 0)),
    ("IPv4 UDP mDNS", hierarchy.get("frame > eth > ip > udp > mdns", 0)),
    ("ARP", hierarchy.get("frame > eth > arp", 0)),
]
protocols = [(name, count) for name, count in protocols if count > 0]


# ---------------------------- DYNAMIC TEST RESULTS ----------------------------

test_results = [
    ("Runtime sensitive logging", "Confirmed", "Frida intercepted two android.util.Log.e() calls. Logcat contains three DIVA error entries.", "Test values appeared in runtime logs; external disclosure was not demonstrated.", "Medium"),
    ("SQL injection – Input Validation Part 1", "Demonstrated in UI test", "The tautology input ' OR '1'='1 reportedly returned three records in the instrumented DIVA build.", "The saved SQL Logcat does not independently record the query result.", "High"),
    ("APICredsActivity", "Confirmed", "The activity was launched and displayed Vendor API key, username and password fields in clear text.", "Credential validity and access by a separate ordinary third-party app were not tested.", "High"),
    ("APICreds2Activity PIN", "Invalid PIN rejected", "The PIN screen was launched; the attempted PIN was rejected with an invalid-PIN response.", "No PIN bypass or credential disclosure was demonstrated.", "Not rated"),
    ("NotesProvider read", "Confirmed", "An ADB shell query to the /notes content URI returned six note records.", "A separate unprivileged third-party application caller was not tested.", "High"),
    ("SharedPreferences", "Observed", "The app preference XML contained user=testuser and password=testuser in plain text when inspected with run-as.", "run-as uses debug-authorised access; ordinary-app access to the private file was not demonstrated.", "Medium"),
    ("External storage", "Not detected", "No DIVA-specific external-storage data directory was found in the inspected location.", "This does not prove that every external-storage path or runtime condition is safe.", "Not rated"),
    ("Internal SQLite database", "Inconclusive", "Database files were present in app-private storage.", "Valid database extraction and content inspection were not completed.", "Not rated"),
    ("WebView behaviour", "Inconclusive", "The available filtered Logcat output did not provide a DIVA WebView event.", "No WebView weakness was confirmed.", "Not rated"),
    ("Network activity", "Observed; DIVA attribution unconfirmed", "The emulator-wide capture contains 151 frames and 30,112 bytes, including DNS, mDNS, HTTP and TLS observations.", "The capture is not correlated to the DIVA UID or process; do not attribute these connections to DIVA.", "Not rated"),
    ("Backup extraction", "Not demonstrated", "No successful DIVA application-data backup or extraction was recorded.", "Backup extraction was not performed.", "Not rated"),
]



# ---------------------------- CHART / CARD HELPERS ----------------------------

def bar_chart(items, empty="No records were found in the supplied evidence."):
    items = [(str(label), int(value)) for label, value in items if int(value) >= 0]
    if not items or not any(value for _, value in items):
        return f"<p class='muted'>{safe(empty)}</p>"
    maximum = max(value for _, value in items) or 1
    blocks = []
    for label, value in items:
        width = value / maximum * 100
        blocks.append(
            f"<div class='bar-row'><div class='bar-label'>{safe(label)}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{width:.1f}%'></div></div>"
            f"<div class='bar-value'>{value:,}</div></div>"
        )
    return "".join(blocks)


def metric(label, value, note=""):
    return (f"<article class='metric-card'><div class='metric-label'>{safe(label)}</div>"
            f"<div class='metric-number'>{safe(value)}</div>"
            f"<div class='metric-note'>{safe(note)}</div></article>")


def finding_card(title, outcome, description, limitation, tone="neutral"):
    return (
        f"<article class='finding-card'>"
        f"<div class='finding-top'><h3>{safe(title)}</h3><span class='status {tone}'>{safe(outcome)}</span></div>"
        f"<p>{safe(description)}</p>"
        f"<div class='limitation'>{safe(limitation)}</div></article>"
    )

def time_label(timestamp):
    if timestamp is None:
        return "Not available"
    return dt.datetime.fromtimestamp(
        timestamp,
        dt.timezone(dt.timedelta(hours=5, minutes=30))
    ).strftime("%d %b %Y, %H:%M:%S")




dns_counts = Counter(pcap["dns"])
protocol_total = sum(value for _, value in protocols)
unique_dns = sorted(set(pcap["dns"]))
unique_tls = sorted(set(pcap["tls_names"]))

# Keep the two values exactly as recorded by Frida. They are test inputs.
frida_value_cards = "".join(
    f"<article class='value-card'><div class='small-label'>Intercepted test value {i}</div>"
    f"<div class='test-value'>{value}</div></article>"
    for i, value in enumerate(("1234567890", "0987665443322111"), 1)
)

findings = [
    finding_card(
        "Runtime sensitive logging", "Confirmed",
        "Frida intercepted 2 android.util.Log.e() calls. Android Logcat contains 3 DIVA error entries. "
        "The two intercepted test values were 1234567890 and 0987665443322111.",
        "These are test values. Log output alone does not show that the values were sent outside the device.",
        "confirmed"
    ),
    finding_card(
        "SQL injection – Input Validation Part 1", "Demonstrated in UI test",
        "The input ' OR '1'='1 reportedly returned 3 records in the instrumented DIVA test.",
        "The saved SQL Logcat file does not independently record the query result.",
        "high"
    ),
    finding_card(
        "APICredsActivity", "Confirmed",
        "The activity opened and displayed Vendor API key, API username and API password in clear text.",
        "Credential validity and access by a separate ordinary third-party app were not tested.",
        "high"
    ),
    finding_card(
        "APICreds2Activity", "PIN rejected",
        "The PIN-entry activity opened. The attempted PIN was rejected as invalid.",
        "No PIN bypass or credential disclosure was demonstrated.",
        "confirmed"
    ),
    finding_card(
        "NotesProvider", "Read confirmed",
        "An ADB shell query to the /notes content URI returned 6 note records.",
        "A separate ordinary third-party application caller was not tested.",
        "high"
    ),
    finding_card(
        "SharedPreferences", "Plain-text values observed",
        "The app preference file contained user=testuser and password=testuser.",
        "The file was inspected with run-as, which uses debug-authorised access. Ordinary-app access was not demonstrated.",
        "medium"
    ),
    finding_card(
        "External storage", "Not detected",
        "No DIVA-specific external-storage data directory was found in the inspected location.",
        "No external-storage exposure was established by this test.",
        "neutral"
    ),
    finding_card(
        "Internal SQLite database", "Inconclusive",
        "The app-private storage contained divanotes.db and sqli database files.",
        "Valid database extraction and content inspection were not completed.",
        "neutral"
    ),
    finding_card(
        "WebView behaviour", "Inconclusive",
        "The collected filtered Logcat output contained no usable DIVA WebView event.",
        "No WebView weakness was confirmed.",
        "neutral"
    ),
    finding_card(
        "Network traffic attribution", "Not confirmed",
        "The emulator-wide PCAP contains 151 frames, including DNS, mDNS, HTTP and TLS traffic.",
        "The capture was not correlated with the DIVA UID or process. The observed connections cannot be attributed to DIVA.",
        "neutral"
    ),
    finding_card(
        "Backup extraction", "Not demonstrated",
        "No successful DIVA application-data backup or extraction was recorded.",
        "Backup extraction was not completed.",
        "neutral"
    ),
]

protocol_chart = bar_chart(protocols)
dns_chart = bar_chart(dns_counts.most_common(8))
runtime_chart = bar_chart([
    ("Frida Log.e() calls", len(frida_messages)),
    ("DIVA Logcat entries", len(logcat_events)),
])
http_tls_chart = bar_chart([
    ("HTTP request lines", len(pcap["http"])),
    ("TLS hostnames", len(unique_tls)),
])

document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIVA Dynamic Analysis</title>
<style>
:root{{--ink:#172b4d;--muted:#64748b;--line:#e4eaf2;--canvas:#f3f6fb;--blue:#416fe1;--teal:#13a58e;--white:#fff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.55 Inter,"Segoe UI",Arial,sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:30px 28px 42px}}
header{{padding:0 0 22px}}
h1{{font-size:28px;line-height:1.2;margin:0 0 8px;font-weight:750;letter-spacing:-.5px}}
.subtitle{{font-size:13px;color:var(--muted)}}
h2{{font-size:17px;margin:0 0 17px;font-weight:700}}
h3{{font-size:14px;margin:0;font-weight:700}}
.section-title{{font-size:19px;margin:28px 0 13px}}
.metric-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:18px 0 16px}}
.metric-card,.panel,.finding-card{{background:var(--white);border:1px solid var(--line);border-radius:13px;box-shadow:0 3px 12px rgba(30,55,90,.035)}}
.metric-card{{padding:16px 18px;min-height:104px}}
.metric-label,.small-label{{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);font-weight:650}}
.metric-number{{font-size:29px;font-weight:760;line-height:1.25;margin:8px 0 3px;color:#142c52}}
.metric-note{{font-size:11px;color:var(--muted)}}
.grid2{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}}
.panel{{padding:19px 20px;min-width:0}}
.bar-row{{display:grid;grid-template-columns:150px minmax(70px,1fr) 35px;gap:10px;align-items:center;margin:15px 0}}
.bar-label{{font-size:12px;color:#42516a;overflow-wrap:anywhere}}
.bar-track{{height:14px;background:#edf1f7;border-radius:20px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:20px;background:linear-gradient(90deg,var(--blue),#5a8be9)}}
.bar-value{{font-size:12px;font-weight:700;text-align:right;color:#203b68}}
.chart-note,.limitation{{font-size:11px;color:var(--muted);background:#f5f8fc;border-left:3px solid #9ab1e8;border-radius:5px;padding:9px 11px;margin-top:15px}}
.finding-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}
.finding-card{{padding:16px 17px;min-width:0}}
.finding-top{{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:8px}}
.finding-card p{{font-size:12px;color:#43516a;margin:7px 0 0}}
.status{{flex-shrink:0;font-size:10px;font-weight:700;padding:4px 8px;border-radius:20px;background:#eef2f7;color:#59677a;text-align:center}}
.status.confirmed{{background:#e8f7f2;color:#14785f}}
.status.high{{background:#fff0ed;color:#b33e32}}
.status.medium{{background:#fff5e5;color:#96630c}}
.value-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}}
.value-card{{border:1px solid var(--line);border-radius:10px;padding:14px;background:#fbfcff}}
.test-value{{font-size:24px;font-weight:750;letter-spacing:.4px;color:#23447e;margin-top:6px}}
.chips{{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}}
.chip{{font-size:11px;color:#38547e;background:#f0f4fb;border:1px solid #e1e8f3;border-radius:7px;padding:6px 9px;overflow-wrap:anywhere}}
.note{{font-size:11px;color:var(--muted);margin-top:12px}}
.footer{{text-align:center;color:var(--muted);font-size:10px;margin-top:25px;padding-top:13px;border-top:1px solid var(--line)}}
@media(max-width:850px){{.metric-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.grid2,.finding-grid{{grid-template-columns:1fr}}}}
@media(max-width:520px){{main{{padding:20px 12px}}h1{{font-size:23px}}.metric-grid{{gap:8px}}.metric-card{{padding:13px}}.bar-row{{grid-template-columns:112px minmax(40px,1fr) 28px;gap:7px}}.value-grid{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff}}main{{max-width:none;padding:12px}}.panel,.metric-card,.finding-card{{box-shadow:none;break-inside:avoid}}}}
</style>
</head>
<body><main>
<header>
<h1>DIVA · Dynamic Security Analysis</h1>
<div class="subtitle">Android Emulator 5554 &nbsp;·&nbsp; Package: {PACKAGE} &nbsp;·&nbsp; Runtime instrumentation &nbsp;·&nbsp; Emulator network capture</div>
</header>

<div class="metric-grid">
{metric("Packets captured", f"{pcap['frames']:,}", f"{pcap['bytes']:,} bytes · diva_final_test.pcap")}
{metric("Frida hook events", len(frida_messages), "android.util.Log.e() intercepted")}
{metric("DNS query packets", len(pcap["dns"]), f"{len(unique_dns)} distinct queried names")}
{metric("HTTP / TLS records", len(pcap["http"]) + len(unique_tls), f"{len(pcap['http'])} HTTP · {len(unique_tls)} TLS hostname")}
</div>

<h2 class="section-title">Activity overview</h2>
<div class="grid2">
<section class="panel"><h2>PCAP protocol distribution</h2>{protocol_chart}
<div class="chart-note">Protocol leaf counts: {safe(" · ".join(f"{name} {value}" for name,value in protocols))}. Nested parent counts are not added.</div></section>
<section class="panel"><h2>DNS query activity</h2>{dns_chart}
<div class="chart-note">Names decoded from DNS packets in the supplied emulator capture.</div></section>
<section class="panel"><h2>Frida and Logcat activity</h2>{runtime_chart}
<div class="chart-note">Frida hook: {"installed" if frida_hooked else "not confirmed"} · Frida attachment: {"confirmed" if frida_attached else "not confirmed"}.</div></section>
<section class="panel"><h2>HTTP and TLS activity</h2>{http_tls_chart}
<div class="chart-note">Network capture is emulator-wide. These records are not confirmed as DIVA-originated traffic.</div></section>
</div>

<h2 class="section-title">Dynamic security test results</h2>
<div class="finding-grid">
{''.join(findings)}
</div>

<h2 class="section-title">Frida intercepted test values</h2>
<section class="panel">
<div class="value-grid">{frida_value_cards}</div>
<div class="note">Values are test inputs observed in the runtime log; they are not verified real payment-card details.</div>
</section>

<h2 class="section-title">Network destinations observed</h2>
<section class="panel">
<div class="chips">{"".join(f"<span class='chip'>{safe(name)}</span>" for name in unique_dns) if unique_dns else "<span class='note'>No DNS names decoded.</span>"}</div>
<p class="note">Capture period: {safe(time_label(pcap['start']))} – {safe(time_label(pcap['end']))}. DIVA process attribution was not established.</p>
</section>

<footer class="footer">DIVA dynamic test observations · Frida, Android Logcat and supplied emulator PCAP</footer>
</main></body></html>"""

OUTPUT.write_text(document, encoding="utf-8")
print("DIVA Dynamic Analysis Dashboard generated.")
print(f"Project folder : {ROOT}")
print(f"Frida events   : {len(frida_messages)}")
print(f"Logcat events  : {len(logcat_events)}")
print(f"PCAP frames    : {pcap['frames']}")
print(f"Packet rows    : {len(packet_rows)}")
print(f"HTML dashboard : {OUTPUT}")
print("Visual format  : bar charts and finding cards only; no tables.")
