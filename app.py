from flask import Flask, render_template, request, redirect, session, Response, flash
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import pickle
import requests
import io
import csv
from features import extract_features

app = Flask(__name__)
app.secret_key = "secret123"

model = pickle.load(open("model.pkl","rb"))

conn = psycopg2.connect(
    database="phishing",
    user="postgres",
    password="pratik",
    host="localhost",
    port="5432"
)

cursor = conn.cursor()

# ---------------- FIX DB LOCK ERROR ----------------
@app.before_request
def cleanup_db():
    try:
        conn.rollback()
    except:
        pass


# ---------------- LOGIN PAGE ----------------
@app.route("/")
def login():
    return render_template("login.html")


# ---------------- SIGNUP PAGE ----------------
@app.route("/signup")
def signup():
    return render_template("signup.html")


# ---------------- REGISTER USER ----------------
@app.route("/register", methods=["POST"])
def register():

    # 🔥 TRIM INPUT (IMPORTANT)
    username = request.form["username"].strip()
    email = request.form["email"].strip()
    password = request.form["password"].strip()

    # 🔥 DEBUG (REMOVE AFTER TEST)
    print("Username length:", len(username))
    print("Email length:", len(email))
    print("Password length:", len(password))

    # 🔥 CHECK EXISTING USER
    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        flash("Email already registered!", "error")
        return redirect("/signup")

    # 🔥 HASH PASSWORD
    hashed_pw = generate_password_hash(password)

    try:
        cursor.execute(
            "INSERT INTO users(username,email,password) VALUES(%s,%s,%s)",
            (username, email, hashed_pw)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("DB ERROR:", e)
        flash("Error: Data too long or invalid input", "error")
        return redirect("/signup")

    flash("Account created successfully!", "success")
    return redirect("/")


# ---------------- LOGIN USER ----------------
@app.route("/login", methods=["POST"])
def login_user():

    email = request.form["email"].strip()
    password = request.form["password"].strip()

    cursor.execute(
        "SELECT id, password FROM users WHERE email=%s",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        flash("Account not found!", "error")
        return redirect("/")

    if check_password_hash(user[1], password):
        session["user_id"] = user[0]
        return redirect("/home")
    else:
        flash("Invalid password!", "error")
        return redirect("/")


# ---------------- HOME ----------------
@app.route("/home")
def home():
    if "user_id" not in session:
        return redirect("/")
    return render_template("index.html")


# ---------------- CHECK URL ----------------
@app.route("/check", methods=["POST"])
def check():

    if "user_id" not in session:
        return redirect("/")

    url = request.form["url"].strip()
    scan_mode = request.form.get("scan_mode", "ai")

    reachable = True

    # 🔥 SAFE REQUEST
    if scan_mode != "fast":
        try:
            req = requests.get(url, timeout=3)
            if req.status_code >= 400:
                reachable = False
        except:
            reachable = False

    features, details = extract_features(url)

    obfuscation_score = min(100, (features[6]*50) + (features[15]*50) + (features[14]*50))
    complexity_score = min(100, (features[3]/1.5) + (features[1]*20))
    keyword_score = min(100, features[11] * 33)
    trust_score = min(100, (features[10]*50) + (features[12]*50))
    density_score = min(100, (features[16]*10) + (features[17]*10) + (features[18]*10) + (features[19]*10))
    radar_data = [int(obfuscation_score), int(complexity_score), int(keyword_score), int(trust_score), int(density_score)]


    if scan_mode == "fast":
        details['Scan Mode'] = "Fast Scan"
    elif scan_mode == "secure":
        details['Scan Mode'] = "Secure Scan"
    else:
        details['Scan Mode'] = "AI Protection"

    phishing_prob = model.predict_proba([features])[0][1]
    score = int(phishing_prob * 100)

    if scan_mode == "secure" and url.startswith("http://"):
        score = max(score, 85)
        details['Secure Mode Error'] = "Risk score artificially elevated due to insecure HTTP connection."

    if score >= 70:
        prediction = "⚠️ Phishing Website"
    elif score >= 40:
        prediction = "⚠️ Suspicious Website"
    else:
        prediction = "✅ Safe Website"

    user_id = session["user_id"]

    try:
        cursor.execute(
            "INSERT INTO scan_history(user_id,url,result) VALUES(%s,%s,%s)",
            (user_id, url, prediction)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("DB ERROR:", e)

    return render_template("result.html",
                           prediction=prediction,
                           url=url,
                           reachable=reachable,
                           details=details,
                           score=score,
                           radar_data=radar_data)


# ---------------- HISTORY ----------------
@app.route("/history")
def history():

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    cursor.execute(
        "SELECT url,result,scan_time FROM scan_history WHERE user_id=%s ORDER BY scan_time DESC",
        (user_id,)
    )

    data = cursor.fetchall()

    return render_template("history.html", data=data)


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    cursor.execute("SELECT result, scan_time FROM scan_history WHERE user_id=%s ORDER BY scan_time ASC", (user_id,))
    all_scans = cursor.fetchall()

    safe_count = sum(1 for row in all_scans if "Safe" in row[0])
    phishing_count = sum(1 for row in all_scans if "Phishing" in row[0])
    suspicious_count = sum(1 for row in all_scans if "Suspicious" in row[0])

    from collections import defaultdict
    daily_counts = defaultdict(int)
    for row in all_scans:
        if row[1]:
            date_str = row[1].strftime("%b %d")
            daily_counts[date_str] += 1
            
    dates = list(daily_counts.keys())[-7:]
    counts = [daily_counts[d] for d in dates]

    return render_template("dashboard.html", 
                           safe=safe_count, 
                           phishing=phishing_count, 
                           suspicious=suspicious_count,
                           dates=dates, 
                           counts=counts)


# ---------------- DOWNLOAD CSV ----------------
@app.route("/download_history")
def download_history():

    if "user_id" not in session:
        return redirect("/")

    user_id = session["user_id"]

    cursor.execute(
        "SELECT url, result, scan_time FROM scan_history WHERE user_id=%s ORDER BY scan_time DESC",
        (user_id,)
    )

    data = cursor.fetchall()

    def generate():
        data_io = io.StringIO()
        writer = csv.writer(data_io)
        writer.writerow(["URL", "Result", "Scan Time"])

        for row in data:
            writer.writerow(row)
            yield data_io.getvalue()
            data_io.seek(0)
            data_io.truncate(0)

    return Response(generate(),
                    mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=scan_history.csv"})


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect("/")


# ---------------- EMAIL SCANNER ----------------
@app.route("/email")
def email():
    if "user_id" not in session:
        return redirect("/")
    return render_template("email.html")

@app.route("/check_email", methods=["POST"])
def check_email():
    if "user_id" not in session:
        return redirect("/")

    email_text = request.form.get("email_text", "")
    
    # Simple NLP logic to analyze the email
    import re
    
    suspicious_keywords = ["urgent", "action required", "verify", "password", "bank", "account suspended", "login", "confirm", "update"]
    found_keywords = [word for word in suspicious_keywords if word in email_text.lower()]
    
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    
    score = 0
    if len(found_keywords) > 0:
        score += 30 + (len(found_keywords) * 10)
    
    if len(urls) > 0:
        score += 20 + (len(urls) * 5)
        
    score = min(score, 100)
    
    if score >= 70:
        prediction = "⚠️ Phishing Email"
    elif score >= 40:
        prediction = "⚠️ Suspicious Email"
    else:
        prediction = "✅ Safe Email"
        
    details = {
        'keywords': found_keywords,
        'urls': urls
    }

    user_id = session["user_id"]
    try:
        # We just insert into the existing history table
        cursor.execute(
            "INSERT INTO scan_history(user_id,url,result) VALUES(%s,%s,%s)",
            (user_id, f"Email Scan: {email_text[:30]}...", prediction)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("DB ERROR:", e)

    return render_template("email_result.html", prediction=prediction, score=score, details=details)


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)