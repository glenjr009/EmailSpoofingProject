🛡️ V0RTEX // MAIL_GUARD
Advanced Forensic Email Analysis & Spoofing Detection System > Developed by Team Trojan Trolls

🕵️‍♂️ Overview
V0RTEX // MAIL_GUARD is a forensic cybersecurity tool designed to analyze .eml files for indicators of spoofing, phishing, and identity deception.

Unlike standard spam filters that rely solely on SPF/DKIM pass tags, V0RTEX employs a "Zero Trust" Structural Consistency approach. It cross-references the sender's identity against technical headers, message fingerprints, and content anomalies to detect sophisticated spoofing attempts that might bypass traditional gateways.

🚀 Key Features
🧠 Intelligent Analysis Engine
Auth Integrity Check: Detects Message-ID vs. From header mismatches and verifies Return-Path alignment.

Header Anomaly Detection: Flags the use of scripting tools (e.g., PHPMailer, Python Scripts) often used in attacks.

Content Risk Assessment: Scans for urgency triggers ("Verify Now", "Suspended") and suspicious external linking patterns.

💻 Cyberpunk Dashboard
Real-time Visualization: Interactive charts powered by Chart.js breaking down threat metrics.

Forensic Logs: Detailed, line-by-line breakdown of why an email was flagged.

Dark Mode UI: A "Hacker Terminal" aesthetic using Orbitron and JetBrains Mono fonts for maximum readability in low-light SOC environments.

📊 Reporting
CSV Export: Download full forensic reports for documentation and further analysis.


## 🛠️ Installation & Setup

### Prerequisites
* Python 3.8+
* pip

### 1. Clone the Repository
```bash
git clone https://github.com/glenjr009/v0rtex-mail-guard.git
cd v0rtex-mail-guard

```
```bash
pip install flask flask-session
```

### 2. Run the Application
```Bash

python app.py
```
### 3. Access the Dashboard
Open your browser and navigate to: http://127.0.0.1:5000

📂 Project Structure
Bash

v0rtex-mail-guard/
│
├── app.py              # Main Flask Application (Routes & UI)
├── detector.py         # Core Forensic Logic (The "Brain")
├── flask_session/      # Server-side session storage (Auto-generated)
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
🧠 How It Works (The Logic)
The tool calculates a total Risk Score based on three vectors:

Auth Score (Identity): * Does the Message-ID domain match the Sender?

Does the Return-Path route back to the claimed sender?

Header Score (Technical):

Are there traces of PHP scripts or automated mailing tools (X-Mailer)?

Are there conflicting Reply-To addresses?

Content Score (Behavioral):

Are there high-pressure keywords ("Urgent", "Password")?

Do links point to domains unrelated to the sender?

Verdict Thresholds:

🟢 Legitimate: Score = 0

🟡 Suspicious: Score < 30

🔴 Likely Spoof: Score ≥ 30
