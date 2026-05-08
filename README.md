# 🛡️ SecureGuard: Phishing Detection System

SecureGuard is a comprehensive, AI-powered cybersecurity web application designed to protect users from malicious URLs and phishing emails. The system leverages Machine Learning (ML) features, Natural Language Processing (NLP) heuristics, and advanced data visualization to provide real-time threat analysis and user analytics.

## ✨ Key Features

1. **AI-Powered URL Scanner** 
   - Extracts 20+ specific lexical, structural, and network features from a URL.
   - Evaluates the URL using a pre-trained Machine Learning model (`model.pkl`) to determine the exact probability of it being a phishing attempt.
   - **Three Scan Modes:**
     - ⚡ **Fast Scan:** Skips network reachability tests for instant, low-latency AI checks.
     - 🛡️ **AI Protection (Standard):** Full analysis including connection tests.
     - 🔒 **Secure Mode:** Highly rigid mode that automatically flags insecure HTTP protocols.

2. **Email Phishing Scanner**
   - Allows users to paste full email bodies for analysis.
   - Utilizes NLP-based rule heuristics to scan for highly manipulative industry keywords ("Urgent", "Action Required", "Suspended Account").
   - Automatically extracts and targets hidden links within the email body.

3. **Threat Radar Visualization**
   - Uses **Chart.js** to dynamically generate a specific multi-axis Spider/Radar chart on the scanning result page.
   - Breaks down the specific URL risk across 5 categories: *Lexical Obfuscation, Structure Complexity, Keyword Threat, Domain Trust, and Symbol Density.*

4. **Personal Analytics Dashboard**
   - A dedicated user dashboard powered by Postgres and **Chart.js**.
   - **Doughnut/Pie Chart:** Visualizes the user's historical ratio of Safe vs. Suspicious vs. Phishing endpoints.
   - **Bar Chart:** Chronologically maps the user's scan volume across the trailing 7 days.

5. **Robust Authentication & History**
   - Built-in signup and login portals using Werkzeug password hashing.
   - Protects duplicate emails and routes users dynamically via Flask Flash messages.
   - Maintains a persistent, downloadable user history mapping timestamps to URLs and threat outcomes.

---

## 🛠️ Technology Stack

- **Backend Logic:** Python 3, Flask framework
- **Machine Learning:** Scikit-Learn, Pickle, Werkzeug
- **Database Architecture:** PostgreSQL (`psycopg2`)
- **Frontend / UI:** HTML5, CSS3, Jinja2 Templating
- **Data Visualization:** Chart.js Library
- **Regex & NLP Analysis:** Native Python `re`

---

## 🚀 Setup & Installation

### 1. Prerequisites
Ensure you have the following installed on your machine:
- Python (3.7+)
- PostgreSQL (running locally on port `5432`)

### 2. Database Configuration
1. Open PostgreSQL (via pgAdmin or SQL Shell).
2. Create a database named exactly `phishing`.
3. Create the required tables (e.g. `users` and `scan_history`). Note: The `password` column in the `users` table must be `VARCHAR(255)` to accommodate modern hash algorithms. 
4. Ensure the Postgres superuser is `postgres` with the password `pratik` (or update `app.py` to match your local credentials!).

### 3. Install Python Dependencies
Open your terminal inside the project directory and run:
```bash
pip install flask psycopg2 Werkzeug requests scikit-learn
```

### 4. Running the Application
To start the Flask local server, run:
```bash
python app.py
```
After initialization, navigate to `http://127.0.0.1:5000` in any modern web browser to access the portal!

---

## 🧠 Machine Learning Details
The backend `features.py` script specifically strips the URL down into mathematical parameters. It searches for specific TLDs (like `.xyz`), assesses subdomain depths, counts suspicious routing symbols (like `@` or `//`), checks for IP addresses obfuscated as domain names, and calculates string lengths. 

These integer parameters are passed to `model.predict_proba()` to generate a Risk Percentage (`0-100%`) rather than a basic binary output, allowing the frontend to dynamically shift UI colors (Green, Yellow, Red) based on threat severity!
