import os
import mysql.connector
from flask import Flask, render_template, request, redirect, url_for , session
from werkzeug.security import generate_password_hash, check_password_hash
from windows_analyzer import analyze_windows_log
from Linux_analyzer import analyze_system_log


app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



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




@app.route('/upload_windows', methods=['POST'])
def upload_windows():

    if 'logfile' not in request.files:
        return "No file uploaded"
   
    file = request.files['logfile']
  
    if file.filename == '':
        return "No selected file"

    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    file.save(filepath)

    results = analyze_windows_log(filepath)

    return render_template("result.html", results=results)



@app.route('/upload_Linux', methods=['POST'])
def upload_Linux():

    if 'logfile' not in request.files:
        return "No file uploaded"

    file = request.files['logfile']

    if file.filename == '':
        return "No selected file"

    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    file.save(filepath)

    results = analyze_system_log(filepath)

    return render_template("result.html", results=results)



@app.route('/Linux_logs')
def Linux_logs():
    return render_template("Linux_logs.html")



if __name__ == '__main__':
    app.run(debug=True)