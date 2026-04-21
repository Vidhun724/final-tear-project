import os
import mysql.connector
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv   # ✅ NEW

from windows_analyzer import analyze_windows_log
from Linux_analyzer import analyze_system_log
from application_analyzer import analyze_application_log
from webserver_analyzer import analyze_webserver_log


# ✅ LOAD .env FILE
load_dotenv()

# ✅ GET API KEY FROM .env
API_KEY = os.getenv("OPENROUTER_API_KEY")


app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.secret_key = "mysecretkey123"


# ---------------- DATABASE ----------------
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="12345",
        database="ai_security_platform"
    )


# ---------------- BASIC ROUTES ----------------
@app.route('/')
def home():
    return render_template("index.html")


@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template("signup.html")


@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['email']
    password = request.form['password']

    hashed_password = generate_password_hash(password)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)",
            (email, hashed_password)
        )

        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for('login_page'))

    except mysql.connector.IntegrityError:
        return "<body style='background:black'><center><h1 style='color:red;'>Email already registered ❌</h1></center></body>"


@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['user'] = email
        return redirect(url_for('Dashboard'))
    else:
        return "<body style='background:black'><center><h1 style='color:red;'>Invalid Email or Password ❌</h1></center></body>"


@app.route('/Dashboard')
def Dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template("Dashboard.html")


@app.route('/about')
def about():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    
    return render_template("about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        print("New Contact Message:")
        print("Name:", name)
        print("Email:", email)
        print("Message:", message)

        return "<center><h2 style='color:green;'>Message Sent Successfully!</h2><a href='/Dashboard'>Back to Dashboard</a></center>"

    return render_template('contact.html')


@app.route('/upload_test', methods=['POST'])
def upload_test():

    if 'logfile' not in request.files:
        return "No file uploaded"

    file = request.files['logfile']

    if file.filename == '':
        return "No selected file"

    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    file.save(filepath)

    return "File saved successfully!"


@app.route('/windows_logs')
def windows_logs():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    
    return render_template("windows_logs.html")




# ---------------- LOG ANALYSIS ----------------
@app.route('/upload_windows', methods=['POST'])
def upload_windows():
    file = request.files['logfile']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    results = analyze_windows_log(filepath)

    return render_template("result.html", results=results, log_type="Windows Security Log")


@app.route('/upload_Linux', methods=['POST'])
def upload_Linux():
    file = request.files['logfile']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    results = analyze_system_log(filepath)

    return render_template("result.html", results=results, log_type="Linux Security Log")


@app.route('/Linux_logs')
def Linux_logs():
    return render_template("Linux_logs.html")


@app.route('/upload_application', methods=['POST'])
def upload_application():
    file = request.files['logfile']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    results = analyze_application_log(filepath)

    return render_template("result.html", results=results, log_type="Application Logs")



@app.route('/Application_logs')
def Application_logs():
    return render_template("Application_logs.html")


@app.route('/upload_webserver', methods=['POST'])
def upload_webserver():
    file = request.files['logfile']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    results = analyze_webserver_log(filepath)

    return render_template("result.html", results=results, log_type="Web Server Logs")


@app.route('/webserver_logs')
def webserver_logs():
    return render_template("webserver_logs.html")


# ---------------- CHATBOT PAGE ----------------
@app.route("/chatbot")
def chatbot():
    attack = request.args.get("attack")
    severity = request.args.get("severity")
    evidence = request.args.get("evidence")

    return render_template(
        "chatbot.html",
        attack=attack,
        severity=severity,
        evidence=evidence
    )


# ---------------- AI CHAT ----------------
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message")

    if not user_message:
        return {"reply": "Please enter a message"}

    try:
        prompt = f"""
        You are a cybersecurity assistant.

        Answer clearly and simply.

        User Question:
        {user_message}
        """

        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "meta-llama/llama-3-8b-instruct",
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=10
        )

        data = response.json()

        if "choices" in data:
            reply = data["choices"][0]["message"]["content"]
        else:
            reply = "AI service is temporarily unavailable."

        return {"reply": reply}

    except Exception as e:
        return {"reply": "Error: " + str(e)}


# ---------------- AUTO EXPLAIN ----------------
@app.route("/auto_explain", methods=["POST"])
def auto_explain():
    data = request.get_json()

    prompt = f"""
    You are a cybersecurity expert.

    Explain this attack:

    Attack: {data.get("attack")}
    Severity: {data.get("severity")}
    Evidence: {data.get("evidence")}

    Give:
    1. Explanation
    2. Risk
    3. Prevention
    """

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "meta-llama/llama-3-8b-instruct",
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=10
        )

        data = response.json()

        if "choices" in data:
            reply = data["choices"][0]["message"]["content"]
        else:
            reply = "AI service is temporarily unavailable."

        return {"reply": reply}

    except Exception as e:
        return {"reply": "Error: " + str(e)}


# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)