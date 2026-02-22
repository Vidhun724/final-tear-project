import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for , session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = "mysecretkey123"

# ---------------- DATABASE PATH FIX ----------------
# find project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# database location
DB_PATH = os.path.join(BASE_DIR, "database", "users.db")
# ---------------------------------------------------
@app.route('/')
def home():
    return render_template("index.html")




# ---------------- SIGNUP PAGE (GET) ----------------
@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template("signup.html")
# ---------------------------------------------------


# ---------------- HANDLE SIGNUP (POST) --------------
@app.route('/signup', methods=['POST'])
def signup():

    email = request.form['email']
    password = request.form['password']

    # hash password (security)
    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect(url_for('login_page'))

    except sqlite3.IntegrityError:
        return "<body style='background:black'><center><h1 style='color:red;'>Email already registered ❌</h1><hr></center></body>"
# ---------------------------------------------------


# ---------------- LOGIN PAGE ----------------
@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")
# --------------------------------------------


# ---------------- HANDLE LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():

    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    conn.close()

    # verify password
    if user and check_password_hash(user[0], password):
        session['user'] = email
        return redirect(url_for('Dashboard'))
    else:
        return "<body style='background:black'><center><h1 style='color:red;'>Invalid Email or Password ❌</h1><hr></center></body>"
# ---------------------------------------------------


# ---------------- UPLOAD PAGE ----------------
@app.route('/Dashboard')
def Dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    
    return render_template("Dashboard.html")
# ---------------------------------------------


# ---------------- RUN SERVER ----------------
if __name__ == '__main__':
    app.run(debug=True)
# ---------------------------------------------

 