from pathlib import Path
import sys
import io
import html
import json
import re
import hashlib
from datetime import datetime, timezone

import pandas as pd
from flask import (
    Flask, request, jsonify, render_template_string, send_file
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from engine import analyze_dataframe, verify_hash_chain

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

SAMPLE_FILE = BASE / "sample_logs.csv"
REPORT_DIR = BASE / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# Demonstration storage. Statuses reset when the server restarts.
review_status = {}
latest = {"result": None, "ledger": None}


def mask_value(value):
    value = str(value or "unknown")
    if value == "unknown":
        return value
    return value[:1] + "***"


def analyze_frame(df):
    result = analyze_dataframe(df)

    # Keep the latest result in memory for this demonstration.
    latest["result"] = result
    latest["ledger"] = result.get("ledger", [])

    for index, incident in enumerate(result.get("incidents", [])):
        incident_id = incident.get("incident_id", f"INC-{index + 1:03d}")
        review_status.setdefault(incident_id, "Pending")

    return result


def get_result():
    if latest["result"] is not None:
        return latest["result"]

    if not SAMPLE_FILE.exists():
        raise FileNotFoundError("Sample logs are missing.")

    return analyze_frame(pd.read_csv(SAMPLE_FILE))


def find_incident(incident_id):
    result = get_result()

    for index, incident in enumerate(result.get("incidents", [])):
        iid = incident.get("incident_id", f"INC-{index + 1:03d}")
        if iid == incident_id:
            item = dict(incident)
            item["incident_id"] = iid
            item["review_status"] = review_status.get(iid, "Pending")
            return item

    return None


def create_pdf(incident):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=42, leftMargin=42,
        topMargin=42, bottomMargin=42
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#167D91"),
        spaceBefore=12, spaceAfter=6
    ))

    def p(value):
        return Paragraph(
            html.escape(str(value if value not in (None, "") else "Not recorded")),
            styles["BodyText"]
        )

    story = [
        Paragraph("HEXATRACE Incident Investigation Report", styles["Title"]),
        Spacer(1, 12),
        p("This report summarizes recorded events and possible relationships. "
          "A correlation or risk score alone does not prove an attack."),
        Paragraph("1. Incident overview", styles["Section"])
    ]

    details = [
        ["Field", "Value"],
        ["Incident ID", incident["incident_id"]],
        ["Severity", incident.get("severity", "Unknown")],
        ["Risk score", f'{incident.get("risk_score", "N/A")}/100'],
        ["Analyst status", incident.get("review_status", "Pending")],
        ["First event", incident.get("start_time", "Not recorded")],
        ["Last event", incident.get("end_time", "Not recorded")],
        ["Event count", incident.get("event_count", "Not recorded")],
        ["Source IP", incident.get("source_ip_masked", "Masked / unavailable")],
        ["Account", incident.get("user_masked", "Masked / unavailable")]
    ]

    table = Table(details, colWidths=[1.5 * inch, 4.8 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16324F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 7)
    ]))
    story.append(table)

    story.append(Paragraph("2. What happened?", styles["Section"]))
    story.append(p(
        "HEXATRACE grouped the following events because they share attributes "
        "used by its correlation engine. This is a lead for investigation, "
        "not confirmation of malicious activity."
    ))

    story.append(Paragraph("3. Incident reconstruction", styles["Section"]))
    timeline = incident.get("timeline", [])
    if timeline:
        for i, event in enumerate(timeline, 1):
            story.append(p(
                f'{i}. Time: {event.get("timestamp", "Unknown")}; '
                f'event: {event.get("event_type", "Unknown")}; '
                f'ID: {event.get("event_id", "Unknown")}'
            ))
            story.append(p(
                "Explanation: " + str(event.get(
                    "explanation", "No explanation recorded"
                ))
            ))
    else:
        story.append(p("No timeline entries were supplied."))

    story.append(Paragraph("4. Who or what was involved?", styles["Section"]))
    story.append(p(
        "The available source and account identifiers are masked in this report. "
        "Check the original authorized logs for device ownership and identity details."
    ))

    story.append(Paragraph("5. How might the events connect?", styles["Section"]))
    story.append(p(
        "The correlation engine groups related records using available attributes. "
        "The sequence may indicate related activity, but the analyst should verify "
        "the relationship using authentication, endpoint and network evidence."
    ))

    story.append(Paragraph("6. Evidence gaps", styles["Section"]))
    gaps = incident.get("evidence_gaps", [])
    for gap in gaps or ["Review original logs and confirm whether additional evidence is required."]:
        story.append(p("- " + str(gap)))

    story.append(Paragraph("7. Recommended next steps", styles["Section"]))
    actions = incident.get("recommended_actions", [])
    for i, action in enumerate(actions or [
        "Validate timestamps and source records.",
        "Check whether the activity was authorized.",
        "Preserve relevant evidence.",
        "Escalate to the security team if the evidence supports an incident."
    ], 1):
        story.append(p(f"{i}. {action}"))

    story.append(Paragraph("8. Analyst decision", styles["Section"]))
    story.append(p(
        "Workflow status: " + incident.get("review_status", "Pending")
    ))
    story.append(p(
        "Completion status is a workflow record, not proof that an attack occurred."
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer


PAGE = r"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HEXATRACE Security Operations</title>
<style>
:root{--bg:#0a1020;--panel:#141f34;--line:#2a3a55;--text:#edf4ff;
--muted:#a4b2c8;--teal:#53e0cb;--red:#ff7889;--amber:#ffd17a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,sans-serif}
header{padding:22px 5%;background:#101a2d;border-bottom:1px solid var(--line)}
.brand{font-size:27px;font-weight:bold;letter-spacing:2px;color:var(--teal)}
main{max-width:1500px;margin:auto;padding:24px}
nav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
button,select,.filebtn{padding:10px 13px;border-radius:7px;border:1px solid var(--line);
background:#1c2a42;color:var(--text);cursor:pointer}
button.primary{background:var(--teal);color:#08151b;border:0;font-weight:bold}
button:disabled{opacity:.4;cursor:not-allowed}
section.panel,.metric,.incident{background:var(--panel);border:1px solid var(--line);
border-radius:12px;padding:18px;margin-bottom:18px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.metric small,.muted{color:var(--muted)}
.metric strong{display:block;font-size:29px;margin-top:10px}
.grid{display:grid;grid-template-columns:1.2fr 1fr;gap:16px}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
td,th{text-align:left;vertical-align:top;padding:11px;border-bottom:1px solid var(--line)}
th{color:var(--muted)}
td{overflow-wrap:anywhere}
.high,.critical{color:var(--red)}.medium{color:var(--amber)}.low{color:var(--teal)}
.hidden{display:none}
.timeline{border-left:2px solid var(--teal);padding-left:14px;margin:14px 0}
.event{margin:12px 0}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
#message{color:var(--teal);margin:12px 0;overflow-wrap:anywhere}
.bar{height:8px;background:#263751;border-radius:5px;margin:7px 0 12px}
.fill{height:8px;background:var(--teal);border-radius:5px}
@media(max-width:850px){.metrics{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
@media(max-width:480px){main{padding:12px}.metrics{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<header>
<div class="brand">HEXATRACE</div>
<p class="muted">Explainable Cyber Risk &amp; Incident Investigation Platform</p>
</header>
<main>
<nav>
<button class="primary" onclick="showTab('dashboard')">Dashboard</button>
<button onclick="showTab('events')">Security Events</button>
<button onclick="showTab('incidents')">Incident Investigation</button>
</nav>

<section id="dashboard">
<section class="panel">
<h2>Investigation Control Center</h2>
<div class="actions">
<button class="primary" onclick="analyzeSample()">Analyze Sample Logs</button>
<input id="csv" type="file" accept=".csv">
<button onclick="uploadLogs()">Upload &amp; Analyze CSV</button>
<button onclick="verifyLedger()">Verify Evidence Chain</button>
</div>
<p class="muted">CSV must include timestamp, event_type and source_ip. Maximum 500 MB.</p>
<div id="message">Run an analysis to begin.</div>
</section>
<div class="metrics">
<div class="metric"><small>Total events</small><strong id="total">—</strong></div>
<div class="metric"><small>Suspicious events</small><strong id="suspicious">—</strong></div>
<div class="metric"><small>High / Critical</small><strong id="high">—</strong></div>
<div class="metric"><small>Maximum risk</small><strong id="risk">—</strong></div>
</div>
<div class="grid">
<section class="panel"><h2>Risk distribution</h2><div id="distribution">No analysis yet.</div></section>
<section class="panel"><h2>Evidence integrity</h2><div id="integrity">No analysis yet.</div>
<p class="muted">A hash chain helps detect changes to retained records; it is not external immutable storage.</p></section>
</div>
</section>

<section id="events" class="hidden">
<section class="panel"><h2>Security Events &amp; Explainable Findings</h2>
<div class="tablewrap"><table><thead><tr>
<th>Time</th><th>Event</th><th>Masked source</th><th>Severity</th><th>Risk</th><th>Why flagged</th><th>Next step</th>
</tr></thead><tbody id="eventRows"></tbody></table></div></section>
</section>

<section id="incidents" class="hidden">
<section class="panel"><h2>Correlated Incidents</h2>
<p class="muted">Review each timeline and evidence gap. PDF reports become available only after the status is marked Done.</p>
<div id="incidentCards">Run an analysis to view incidents.</div>
</section>
</section>
</main>
<script>
let current = null;
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function showTab(id){["dashboard","events","incidents"].forEach(x=>document.getElementById(x).classList.toggle("hidden",x!==id));}
async function call(url,options={}){
 const r=await fetch(url,options); const d=await r.json();
 if(!r.ok) throw Error(d.error||"Request failed"); return d;
}
function status(msg){document.getElementById("message").textContent=msg;}
async function analyzeSample(){
 status("Analyzing sample logs...");
 try{render(await call("/api/analyze/sample",{method:"POST"}));status("Analysis complete.");}
 catch(e){status("Error: "+e.message);}
}
async function uploadLogs(){
 const f=document.getElementById("csv").files[0];
 if(!f){status("Choose a CSV file first.");return;}
 const form=new FormData();form.append("file",f);status("Analyzing uploaded logs...");
 try{render(await call("/api/analyze/upload",{method:"POST",body:form}));status("Upload analysis complete.");}
 catch(e){status("Error: "+e.message);}
}
function render(d){
 current=d;
 document.getElementById("total").textContent=d.total_events;
 document.getElementById("suspicious").textContent=d.suspicious_events;
 document.getElementById("high").textContent=d.high_severity;
 document.getElementById("risk").textContent=d.overall_risk+"/100";
 document.getElementById("integrity").textContent=d.ledger_valid?"Current evidence chain: VALID":"Evidence chain: INVALID";
 const counts={Critical:0,High:0,Medium:0,Low:0};
 d.events.forEach(e=>counts[e.severity]=(counts[e.severity]||0)+1);
 document.getElementById("distribution").innerHTML=Object.entries(counts).map(([k,v])=>
 `<div>${esc(k)}: <b>${v}</b><div class="bar"><div class="fill" style="width:${d.total_events?100*v/d.total_events:0}%"></div></div></div>`).join("");
 document.getElementById("eventRows").innerHTML=d.events.map(e=>
 `<tr><td>${esc(e.timestamp)}</td><td>${esc(e.event_type)}</td>
 <td>${esc(e.source_ip_masked)}</td><td class="${esc(e.severity.toLowerCase())}">${esc(e.severity)}</td>
 <td>${esc(e.risk_score)}/100</td><td>${esc(e.explanation)}</td>
 <td>${esc((e.recommendations||[]).join(" "))}</td></tr>`).join("");
 document.getElementById("incidentCards").innerHTML=d.incidents.map(i=>{
 const done=i.review_status==="Done";
 return `<article class="incident"><h3>${esc(i.incident_id)} — ${esc(i.severity)} — Risk ${esc(i.risk_score)}/100</h3>
 <p class="muted">Source: ${esc(i.source_ip_masked)} | Account: ${esc(i.user_masked)} | Events: ${esc(i.event_count)}</p>
 <p>First: ${esc(i.start_time)} | Last: ${esc(i.end_time)}</p>
 <h4>Incident reconstruction</h4><div class="timeline">${(i.timeline||[]).map(t=>
 `<div class="event"><b>${esc(t.timestamp)} — ${esc(t.event_type)}</b><br>${esc(t.explanation)}</div>`).join("")}</div>
 <h4>Evidence gaps</h4><ul>${(i.evidence_gaps||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul>
 <h4>Recommended actions</h4><ul>${(i.recommended_actions||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul>
 <div class="actions"><label>Analyst status:
 <select id="st-${esc(i.incident_id)}"><option ${i.review_status==="Pending"?"selected":""}>Pending</option>
 <option ${i.review_status==="Approved"?"selected":""}>Approved</option>
 <option ${done?"selected":""}>Done</option></select></label>
 <button onclick="saveStatus('${esc(i.incident_id)}')">Save status</button>
 <button class="primary" ${done?"":"disabled"} onclick="downloadPdf('${esc(i.incident_id)}')">${done?"Download incident PDF":"PDF available when Done"}</button></div>
 <p class="muted">Current status: ${esc(i.review_status||"Pending")}</p></article>`;
 }).join("")||"No correlated incidents found.";
 showTab("dashboard");
}
async function saveStatus(id){
 try{
 const s=document.getElementById("st-"+id).value;
 await call("/api/incidents/"+encodeURIComponent(id)+"/status",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:s})});
 render(await call("/api/incidents"));status("Status saved for "+id+".");
 }catch(e){status("Could not save status: "+e.message);}
}
async function downloadPdf(id){
 try{
 const r=await fetch("/api/incidents/"+encodeURIComponent(id)+"/report.pdf");
 if(!r.ok){const d=await r.json();throw Error(d.error||"PDF unavailable");}
 const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=url;a.download="HEXATRACE_"+id+".pdf";a.click();URL.revokeObjectURL(url);
 }catch(e){status("PDF error: "+e.message);}
}
async function verifyLedger(){
 try{const d=await call("/api/verify");document.getElementById("integrity").textContent=d.valid?"Evidence chain verification PASSED":"Evidence chain verification FAILED";}
 catch(e){status("Verification error: "+e.message);}
}
</script>
</body></html>
"""


@app.get("/")
def home():
    return render_template_string(PAGE)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "application": "HEXATRACE"})


@app.post("/api/analyze/sample")
def analyze_sample():
    try:
        if not SAMPLE_FILE.exists():
            return jsonify({"error": "sample_logs.csv not found"}), 404
        return jsonify(analyze_frame(pd.read_csv(SAMPLE_FILE)))
    except Exception as exc:
        app.logger.exception("Sample analysis failed")
        return jsonify({"error": str(exc)}), 400


@app.post("/api/analyze/upload")
def analyze_upload():
    try:
        file = request.files.get("file")
        if not file or not file.filename:
            return jsonify({"error": "Choose a CSV file"}), 400
        if not file.filename.lower().endswith(".csv"):
            return jsonify({"error": "Only CSV files are supported"}), 400
        df = pd.read_csv(file, nrows=10001)
        if len(df) > 100000:
            return jsonify({"error": "Maximum 100,000 rows"}), 400
        return jsonify(analyze_frame(df))
    except Exception as exc:
        app.logger.exception("CSV analysis failed")
        return jsonify({"error": str(exc)}), 400


@app.get("/api/incidents")
def list_incidents():
    try:
        result = get_result()
        incidents = []
        for index, item in enumerate(result.get("incidents", [])):
            incident = dict(item)
            iid = incident.get("incident_id", f"INC-{index + 1:03d}")
            incident["incident_id"] = iid
            incident["review_status"] = review_status.get(iid, "Pending")
            incidents.append(incident)
        return jsonify({
            "total_events": result["total_events"],
            "suspicious_events": result["suspicious_events"],
            "high_severity": result["high_severity"],
            "overall_risk": result["overall_risk"],
            "events": result["events"],
            "incidents": incidents,
            "ledger_valid": result["ledger_valid"]
        })
    except Exception as exc:
        app.logger.exception("Incident listing failed")
        return jsonify({"error": str(exc)}), 500


@app.post("/api/incidents/<incident_id>/status")
def set_status(incident_id):
    if incident_id not in {
        i.get("incident_id") for i in get_result().get("incidents", [])
    }:
        return jsonify({"error": "Incident not found"}), 404

    data = request.get_json(silent=True) or {}
    value = data.get("status")
    if value not in {"Pending", "Approved", "Done"}:
        return jsonify({"error": "Status must be Pending, Approved or Done"}), 400

    review_status[incident_id] = value
    return jsonify({"incident_id": incident_id, "review_status": value})


@app.get("/api/incidents/<incident_id>/report.pdf")
def incident_pdf(incident_id):
    incident = find_incident(incident_id)
    if incident is None:
        return jsonify({"error": "Incident not found"}), 404
    if review_status.get(incident_id, "Pending") != "Done":
        return jsonify({"error": "Mark this incident Done before downloading its PDF"}), 403

    buffer = create_pdf(incident)
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", incident_id)
    return send_file(
        buffer, mimetype="application/pdf", as_attachment=True,
        download_name=f"HEXATRACE_{safe_id}_Report.pdf"
    )


@app.get("/api/verify")
def verify():
    if latest["ledger"] is None:
        return jsonify({"error": "Run an analysis first"}), 400
    return jsonify({"valid": verify_hash_chain(latest["ledger"])})




@app.route("/api/report/full.pdf", methods=["GET"])
def download_full_report():
    from io import BytesIO
    from datetime import datetime
    from xml.sax.saxutils import escape
    from flask import send_file, jsonify
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )

    try:
        result = get_result()
        buffer = BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="HEXATraceTitle",
            parent=styles["Title"],
            alignment=1,
            spaceAfter=12,
        ))

        def safe(value):
            if value is None or value == "":
                value = "Not available"
            if isinstance(value, (list, dict)):
                value = str(value)
            return escape(str(value))

        def section(title):
            story.append(Spacer(1, 5 * mm))
            story.append(Paragraph(safe(title), styles["Heading2"]))

        def details_table(rows):
            table = Table(rows, colWidths=[42 * mm, 118 * mm])
            table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1),
                 colors.HexColor("#edf2f7")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)
            story.append(Spacer(1, 3 * mm))

        story = [
            Paragraph(
                "HEXATRACE Security Investigation Report",
                styles["HEXATraceTitle"],
            ),
            Paragraph(
                "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                styles["Normal"],
            ),
        ]

        section("1. Executive Summary")
        details_table([
            ["Metric", "Result"],
            ["Total events", safe(result.get("total_events", 0))],
            ["Suspicious events", safe(result.get("suspicious_events", 0))],
            ["High-severity events", safe(result.get("high_severity", 0))],
            ["Overall risk", safe(result.get("overall_risk", "Unknown"))],
            ["Evidence ledger valid",
             safe(result.get("ledger_valid", "Not verified"))],
        ])

        section("2. Security Event Analysis")
        events = result.get("events", [])

        if not events:
            story.append(Paragraph(
                "No event records are available.", styles["Normal"]
            ))

        for number, event in enumerate(events, start=1):
            story.append(Paragraph(
                f"Event {number}: {safe(event.get('event_type'))}",
                styles["Heading3"],
            ))
            details_table([
                ["Timestamp", safe(event.get("timestamp"))],
                ["Severity", safe(event.get("severity"))],
                ["Risk score", safe(event.get("risk_score"))],
                ["Source IP", safe(event.get("source_ip_masked"))],
                ["Explanation", safe(event.get("explanation"))],
                ["Recommendations", safe(event.get("recommendations"))],
            ])

        section("3. Correlated Incident Investigations")
        incidents = result.get("incidents", [])

        if not incidents:
            story.append(Paragraph(
                "No correlated incidents are available.", styles["Normal"]
            ))

        for number, incident in enumerate(incidents, start=1):
            incident_id = incident.get("incident_id", f"INC-{number:03d}")

            story.append(Paragraph(
                f"Incident {number}: {safe(incident_id)}",
                styles["Heading3"],
            ))

            details_table([
                ["Severity", safe(incident.get("severity"))],
                ["Risk score", safe(incident.get("risk_score"))],
                ["Events correlated", safe(incident.get("event_count"))],
                ["Start time", safe(incident.get("start_time"))],
                ["End time", safe(incident.get("end_time"))],
                ["Source IP", safe(incident.get("source_ip_masked"))],
                ["User", safe(incident.get("user_masked"))],
                ["Timeline", safe(incident.get("timeline"))],
                ["Evidence gaps", safe(incident.get("evidence_gaps"))],
                ["Recommended actions",
                 safe(incident.get("recommended_actions"))],
            ])

        section("4. Analyst Note")
        story.append(Paragraph(
            "This report summarizes the analysis and evidence available "
            "to HEXATRACE. Validate important conclusions against original "
            "security logs before taking action.",
            styles["Normal"],
        ))

        doc.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="HEXATRACE_Full_Analysis_Report.pdf",
        )

    except Exception as exc:
        app.logger.exception("Full PDF report generation failed")
        return jsonify({
            "error": "Could not generate PDF report",
            "details": str(exc),
        }), 500


if __name__ == "__main__":
    print("HEXATRACE integrated dashboard starting on port 5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
