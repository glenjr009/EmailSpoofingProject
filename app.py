import os
import csv
import io
import email
from flask import Flask, request, render_template_string, send_file, session
from flask_session import Session
from detector import analyze_email

app = Flask(__name__)
app.secret_key = "emailsecurekey"

# Session config
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_FILE_DIR"] = os.path.join(app.root_path, 'flask_session')

if not os.path.exists(app.config["SESSION_FILE_DIR"]):
    os.makedirs(app.config["SESSION_FILE_DIR"])

Session(app)

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(errors="ignore")
    return ""

# HTML Template
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>V0RTEX // MAIL_GUARD</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@500;900&display=swap" rel="stylesheet">

    <style>
        body { 
            background-color: #050505; 
            color: #00ff41; 
            font-family: 'JetBrains Mono', monospace; 
            background-image: radial-gradient(circle, #111 1px, transparent 1px);
            background-size: 20px 20px;
        }

        body::before {
            content: " ";
            display: block;
            position: fixed;
            top: 0; left: 0; bottom: 0; right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            z-index: 2;
            background-size: 100% 2px, 3px 100%;
            pointer-events: none;
        }

        h4, h5, .navbar-brand { 
            font-family: 'Orbitron', sans-serif; 
            text-transform: uppercase; 
            letter-spacing: 3px; 
            text-shadow: 0 0 8px #00ff41; 
        }
        
        .navbar { background-color: #000 !important; border-bottom: 1px solid #00ff41; box-shadow: 0 0 15px #00ff4144; }
        .navbar-brand { color: #fff !important; font-weight: 900; }

        .cyber-card {
            background-color: #0a0a0a;
            border: 1px solid #00ff41;
            box-shadow: 0 0 20px #00ff4122;
            padding: 25px;
            border-radius: 8px;
            position: relative;
            z-index: 3;
            margin-top: 30px;
        }

        .form-control {
            background-color: #000;
            border: 1px solid #333;
            color: #00ff41;
            font-family: 'JetBrains Mono', monospace;
        }
        .form-control:focus {
            background-color: #111;
            color: #fff;
            border-color: #00ff41;
            box-shadow: 0 0 10px #00ff41;
        }
        
        .btn-cyber {
            background-color: #00ff41;
            border: none;
            color: #000;
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            letter-spacing: 1px;
            transition: 0.3s;
        }
        .btn-cyber:hover {
            background-color: #fff;
            box-shadow: 0 0 20px #00ff41;
        }

        .btn-download {
            background-color: transparent;
            border: 1px solid #00d2ff;
            color: #00d2ff;
        }
        .btn-download:hover {
            background-color: #00d2ff;
            color: #000;
            box-shadow: 0 0 20px #00d2ff;
        }

        .table { color: #ccc; border-color: #333; font-size: 0.9rem; }
        .table-dark { background-color: #111; color: #00ff41; border-bottom: 2px solid #00ff41; font-family: 'Orbitron', sans-serif; }
        .table-striped tbody tr:nth-of-type(odd) { background-color: #0f0f0f; }
        .table-striped tbody tr:nth-of-type(even) { background-color: #050505; }
        td { vertical-align: middle; border-color: #222; }

        .table tbody tr td:last-child {
            color: #000000 !important;
            background-color: #e0e0e0 !important;
            font-weight: 600;
            font-size: 0.85rem;
            border-left: 3px solid #00ff41;
        }

        .badge-spoof { 
            background-color: rgba(255, 0, 0, 0.1); 
            border: 1px solid red; 
            color: red; 
            padding: 8px 12px; 
            border-radius: 4px;
            font-weight: bold;
            box-shadow: 0 0 5px red;
            white-space: nowrap; 
            display: inline-block;
        }
        .badge-safe { 
            background-color: rgba(0, 255, 65, 0.1); 
            border: 1px solid #00ff41; 
            color: #00ff41; 
            padding: 8px 12px; 
            border-radius: 4px;
            font-weight: bold;
            box-shadow: 0 0 5px #00ff41;
            white-space: nowrap; 
            display: inline-block;
        }

        footer { border-top: 1px dashed #333; margin-top: 80px; color: #666; font-size: 0.8rem; }
        canvas { max-height: 250px; }
    </style>
</head>

<body>

<nav class="navbar navbar-dark mb-4">
    <div class="container-fluid">
        <span class="navbar-brand mx-auto">🛡️ V0RTEX // MAIL_GUARD</span>
    </div>
</nav>

<div class="container cyber-card">
    <h4><span style="color:#00d2ff;">>></span> INITIATE_SCAN_PROTOCOL</h4>
    <p class="text-secondary mb-4">Upload .eml files to detect spoofing anomalies.</p>
    
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="email_files" multiple accept=".eml" class="form-control mb-3">
        <button type="submit" class="btn btn-cyber w-100">RUN DIAGNOSTICS</button>
    </form>

    {% if results %}
    <div style="height: 2px; background: #00ff41; opacity: 0.3; margin: 50px 0;"></div>
    
    <h4><span style="color:#00d2ff;">>></span> SCAN_RESULTS_LOG</h4>
    <div class="table-responsive">
        <table class="table table-bordered table-striped mt-3">
            <thead class="table-dark">
                <tr>
                    <th>ID</th>
                    <th>FILE</th>
                    <th>SUBJECT</th>
                    <th>SCORE</th>
                    <th>AUTH</th>
                    <th>HEADER</th>
                    <th>CONTENT</th>
                    <th>STATUS</th>
                    <th>INTEL</th>
                </tr>
            </thead>
            <tbody>
            {% for r in results %}
            <tr>
                <td>{{ loop.index }}</td>
                <td>{{ r.filename }}</td>
                <td>{{ r.subject }}</td>
                <td>{{ r.score }}</td>
                <td>{{ r.auth_score }}</td>
                <td>{{ r.header_score }}</td>
                <td>{{ r.content_score }}</td>
                <td style="text-align: center;">
                    {% if r.label.startswith('LIKELY') %}
                        <span class="badge-spoof">⚠️ THREAT</span>
                    {% else %}
                        <span class="badge-safe">✅ SECURE</span>
                    {% endif %}
                </td>
                <td>
                    {% for x in r.reasons %}
                        <div>> {{ x }}</div>
                    {% endfor %}
                </td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <h4 class="mt-5 mb-3"><span style="color:#00d2ff;">>></span> THREAT_VISUALIZATION</h4>
    
    <div class="row">
        <div class="col-md-6 mb-4">
            <div class="p-3 border border-secondary rounded bg-black">
                <canvas id="resultChart"></canvas>
            </div>
        </div>
        <div class="col-md-6 mb-4">
            <div class="p-3 border border-secondary rounded bg-black">
                <canvas id="authChart"></canvas>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-6 mb-4">
            <div class="p-3 border border-secondary rounded bg-black">
                <canvas id="contentChart"></canvas>
            </div>
        </div>
        <div class="col-md-6 mb-4">
            <div class="p-3 border border-secondary rounded bg-black">
                <canvas id="headerChart"></canvas>
            </div>
        </div>
    </div>

    <a href="/download_csv" class="btn btn-download w-100 py-2">📥 EXPORT_DATA_LOGS.CSV</a>

    <script>
    Chart.defaults.color = '#888';
    Chart.defaults.borderColor = '#222';
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    
    const results = {{ results|tojson }};
    const spoofCount = results.filter(r => r.label.startsWith("LIKELY")).length;
    const legitCount = results.length - spoofCount;

    const chartOptions = {
        scales: { 
            y: { 
                beginAtZero: true, 
                max: 100,
                grid: { color: '#333' } 
            },
            x: {
                grid: { color: '#333' }
            }
        }
    };

    // Overall Ratio
    new Chart(document.getElementById("resultChart"), {
        type: "doughnut",
        data: {
            labels: ["THREAT DETECTED", "SECURE"],
            datasets: [{
                data: [spoofCount, legitCount],
                backgroundColor: ["#ff3333", "#00ff41"],
                borderColor: "#000",
                borderWidth: 2
            }]
        },
        options: { 
            plugins: { 
                title: { display: true, text: 'THREAT RATIO', color: '#fff', font: {size: 14, family: 'Orbitron'} },
                legend: { labels: { color: '#fff' } }
            } 
        }
    });

    // Auth Integrity
    new Chart(document.getElementById("authChart"), {
        type: "bar",
        data: {
            labels: results.map((r, i) => "MSG_" + (i + 1)),
            datasets: [{
                label: "AUTH INTEGRITY",
                data: results.map(r => r.auth_score),
                backgroundColor: "#00d2ff",
                borderColor: "#00d2ff",
                borderWidth: 1
            }]
        },
        options: chartOptions
    });

    // Content Risk
    new Chart(document.getElementById("contentChart"), {
        type: "bar",
        data: {
            labels: results.map((r, i) => "MSG_" + (i + 1)),
            datasets: [{
                label: "CONTENT RISK",
                data: results.map(r => r.content_score),
                backgroundColor: "#ff3333",
                borderColor: "#ff3333",
                borderWidth: 1
            }]
        },
        options: chartOptions
    });

    // Header Anomalies
    new Chart(document.getElementById("headerChart"), {
        type: "bar",
        data: {
            labels: results.map((r, i) => "MSG_" + (i + 1)),
            datasets: [{
                label: "HEADER ANOMALIES",
                data: results.map(r => r.header_score),
                backgroundColor: "#ffe600",
                borderColor: "#ffe600",
                borderWidth: 1
            }]
        },
        options: chartOptions
    });
    </script>

    {% endif %}
</div>

<footer class="text-center p-4" style="border-top: 1px solid #333; margin-top: 50px;">
    <p>
        CREATED WITH <span style="font-size: 1.2rem;">🐍</span> (PYTHON) & <span style="font-size: 1.2rem;">🛡️</span> (SECURITY)
    </p>
    <p style="color: #00ff41;">
        >> DESIGNED BY 7r0j4n 7r0ll5 <<
    </p>
</footer>

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    results = []

    if request.method == "POST":
        files = request.files.getlist("email_files")

        for file in files:
            if file.filename == "":
                continue

            try:
                raw_bytes = file.read()
                raw = raw_bytes.decode(errors="ignore")

                msg = email.message_from_string(raw)
                body = get_email_body(msg)

                analysis = analyze_email(msg, body, raw_bytes)

                results.append({
                    "filename": file.filename,
                    "subject": msg.get("Subject", "(No Subject)"),

                    "score": analysis["score"],
                    "auth_score": analysis["auth_score"],
                    "header_score": analysis["header_score"],
                    "content_score": analysis["content_score"],
                    "label": analysis["label"],

                    "spf_result": analysis["spf_result"],
                    "spf_reason": analysis["spf_reason"],
                    "dkim_result": analysis["dkim_result"],
                    "dkim_reason": analysis["dkim_reason"],
                    "dmarc_result": analysis["dmarc_result"],
                    "dmarc_reason": analysis["dmarc_reason"],

                    "identity_issues": analysis["identity_issues"],
                    "header_issues": analysis["header_issues"],
                    "content_issues": analysis["content_issues"],
                    "reasons": analysis["reasons"]
                })

            except Exception as e:
                # FIXED INDENTATION HERE ↓↓↓
                results.append({
                    "filename": file.filename,
                    "subject": "Error reading",
                    "score": "-",
                    "label": "ERROR",
                    "auth_score": "-",
                    "header_score": "-",
                    "content_score": "-",
                    "spf_result": "error",
                    "spf_reason": str(e),
                    "dkim_result": "error",
                    "dkim_reason": str(e),
                    "dmarc_result": "error",
                    "dmarc_reason": str(e),
                    "identity_issues": [],
                    "header_issues": [],
                    "content_issues": [],
                    "reasons": [str(e)]
                })

        session["results"] = results

    return render_template_string(HTML, results=results)
@app.route("/download_csv")
def download_csv():
    results = session.get("results", [])

    if not results:
        return "No results available to download", 400

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "File Name", 
        "Subject", 
        "Total Score", 
        "Auth Score", 
        "Header Score", 
        "Content Score",
        "SPF Result",
        "DKIM Result",
        "DMARC Result",
        "Reasons"
    ])

    for r in results:
        reasons_text = "; ".join(r.get("reasons", []))

        writer.writerow([
            r.get("filename", ""),
            r.get("subject", ""),
            r.get("score", ""),
            r.get("auth_score", ""),
            r.get("header_score", ""),
            r.get("content_score", ""),
            r.get("spf_result", ""),
            r.get("dkim_result", ""),
            r.get("dmarc_result", ""),
            reasons_text
        ])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="email_analysis_results.csv"
    )

if __name__ == "__main__":
    app.run(debug=True)
