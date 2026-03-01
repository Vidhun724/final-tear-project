import os
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for , session
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = "mysecretkey123"



def get_db_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="12345",
        database="ai_security_platform"
    )
    return conn


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
        return "<body style='background:black'><center><h1 style='color:red;'>Email already registered ❌</h1><hr></center></body>"


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
        return "<body style='background:black'><center><h1 style='color:red;'>Invalid Email or Password ❌</h1><hr></center></body>"


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




if __name__ == '__main__':
    app.run(debug=True)