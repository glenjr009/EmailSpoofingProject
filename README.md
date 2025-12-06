# 🛡️ Email Spoofing Detection System  
Designed & Developed by **Team Trojan Trolls** 🔥

A smart bulk email analysis tool to detect spoofing and phishing attempts by examining **email headers** and **content patterns**.

---

## ⭐ Features

✔ Upload & analyze **multiple .eml** emails at once  
✔ Detect forged sender identity  
✔ Rule-based scoring engine  
✔ Header + Content + SPF/DKIM checks  
✔ Detailed reasoning for every detection  
✔ Intuitive dashboard UI  
✔ Graphs & statistics for quick insights  
✔ CSV export for reporting  
✔ Secure offline analysis  

---

## 🧠 How It Works

| Module | Description |
|--------|-------------|
| Email Parser | Extracts headers & body using Python email library |
| Header Analyzer | Detects forged sender fields & missing auth |
| Content Analyzer | Keyword-based phishing detection, URL scans |
| SPF/DKIM Check | Reads Authentication-Results indicators |
| Report Generator | CSV export + Graphical insights |

**Scoring System:**

| Score Range | Meaning |
|------------|---------|
| 0–2 | Likely Legit |
| 3–5 | Suspicious |
| 6+ | High Spoof/Phishing Risk |

---

## 🛠️ Tech Used

This project is built using:

- **Python 3** → main development language  
- **Flask** → backend web framework  
- **Bootstrap 5** → modern front-end UI  
- **Chart.js** → create analytics visualizations  
- **Python Email Library** → extract & parse email content  
- **CSV Export Tools** → download report files  

---

## 🚀 Setup & Installation

Follow these steps:

1️⃣ Install **Python 3**  
2️⃣ Open Terminal / VS Code in the project folder  
3️⃣ Install required modules:

```bash
pip install flask

4️⃣ Run the web app:

python app.py


(or)

py app.py


5️⃣ Open the browser and go to:

http://127.0.0.1:5000


6️⃣ Upload .eml files and view results 🔍

“A small shield against a big threat — Email Spoofing!”
<img width="956" height="448" alt="{3D76A33F-8D3E-4F41-8566-BBA010B90B79}" src="https://github.com/user-attachments/assets/bed293bd-87b9-454c-8464-4f0d04dd4b63" />
