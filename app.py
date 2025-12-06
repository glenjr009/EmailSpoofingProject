from flask import Flask, request, render_template_string, send_file, session
app = Flask("EmailSpoofingDetector")
app.secret_key = "emailspoofingsecurekey"
import csv
import io

import email
from detector import analyze_email
from main import get_email_body

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # Any random secure string

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Spoofing Detector</title>

    <!-- Bootstrap -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body { background-color: #f2f2f2; }
        .navbar-brand { font-weight: bold; font-size: 1.4rem; }
        .container-box {
            background: white; padding: 25px; border-radius: 10px;
            box-shadow: 0px 0px 15px rgba(0,0,0,0.15);
            margin-top: 25px;
        }
        footer {
            margin-top: 50px; text-align: center; padding: 10px;
            background: #222; color: #fff; border-radius: 6px;
        }
        th { background-color: #007bff !important; color: white; }
        .spoof { color: red; font-weight: bold; }
        .legit { color: green; font-weight: bold; }
    </style>

</head>
<body>

    <!-- Navbar -->
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <span class="navbar-brand">
                🛡️ Email Spoofing Detection System
            </span>
        </div>
    </nav>


    <div class="container container-box">

        <h3>Upload Email Files (.eml) for Bulk Analysis</h3>
        <form method="POST" enctype="multipart/form-data">
            <input class="form-control" type="file" name="email_files" multiple accept=".eml">
            <button class="btn btn-primary mt-3" type="submit">Analyze Emails</button>
        </form>


        {% if results %}
        <h3 class="mt-4">Results ({{ results | length }} analyzed)</h3>

        <table class="table table-bordered table-hover mt-3">
            <thead>
                <tr>
                    <th>#</th>
                    <th>File Name</th>
                    <th>Subject</th>
                    <th>Total Score</th>
                    <th>Result</th>
                    <th>Reasons</th>
                </tr>
            </thead>
            <tbody>
            {% for r in results %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td>{{ r.filename }}</td>
                    <td>{{ r.subject }}</td>
                    <td>{{ r.score }}</td>
                    <td class="{% if r.label.startswith('LIKELY SPOOFED') %}spoof{% else %}legit{% endif %}">
                        {{ r.label }}
                    </td>
                    <td>
                        <ul>
                        {% for reason in r.reasons %}
                            <li>{{ reason }}</li>
                        {% endfor %}
                        </ul>
                    </td>
                </tr>
            {% endfor %}
            </tbody>
        </table>

        <!-- CSV Download -->
        <a href="/download_csv" class="btn btn-success mb-3">Download Results as CSV</a>

        <!-- Graphs -->
        <h4>Visualization</h4>
        <canvas id="resultChart" height="120"></canvas>
        <canvas id="scoreChart" height="120" class="mt-3"></canvas>


        <script>
            const results = {{ results|tojson }};
            const spoofCount = results.filter(r => r.label.startsWith("LIKELY SPOOFED")).length;
            const legitCount = results.length - spoofCount;

            new Chart(document.getElementById("resultChart"), {
                type: "pie",
                data: {
                    labels: ["Spoofed", "Legit"],
                    datasets: [{ data: [spoofCount, legitCount] }]
                }
            });

            const headerScores = results.map(r => r.header_score);
            const contentScores = results.map(r => r.content_score);

            new Chart(document.getElementById("scoreChart"), {
                type: "bar",
                data: {
                    labels: results.map((r, i) => "Email " + (i+1)),
                    datasets: [
                        { label: "Header Score", data: headerScores },
                        { label: "Content Score", data: contentScores }
                    ]
                }
            });
        </script>

        {% endif %}

    </div>


    <!-- Footer -->
    <footer>
        © 7r0J4N 7r0115 — Mini Project 2025 | Guided by: _Prof. Sagar Pujar_
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
            try:
                raw = file.read().decode(errors="ignore")
                msg = email.message_from_string(raw)
                body = get_email_body(msg)
                analysis = analyze_email(msg, body)

                results.append({
                    "filename": file.filename,
                    "subject": msg.get("Subject", "(No Subject)"),
                    "score": analysis["score"],
                    "label": analysis["label"],
                    "header_score": analysis["header_score"],
                    "content_score": analysis["content_score"],
                    "reasons": analysis["reasons"]
                })

            except Exception as e:
                results.append({
                    "filename": file.filename,
                    "subject": "Error reading",
                    "score": "-",
                    "label": "ERROR",
                    "header_score": "-",
                    "content_score": "-",
                    "reasons": [str(e)]
                })
    session["results"] = results
    return render_template_string(HTML, results=results)


if __name__ == "__main__":
    app.run(debug=True)
@app.route("/download_csv")
def download_csv():
    results = session.get("results", [])
    
    if not results:
        return "No results available to download", 400

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["File Name", "Subject", "Total Score", "Result", "Reasons"])

    for r in results:
        reasons_text = "; ".join(r["reasons"])
        writer.writerow([r["filename"], r["subject"], r["score"], r["label"], reasons_text])

    output.seek(0)

    return send_file(io.BytesIO(output.getvalue().encode()),
                     mimetype="text/csv",
                     download_name="email_analysis_results.csv",
                     as_attachment=True)
