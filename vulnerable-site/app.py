from flask import Flask, request, render_template, redirect, session,flash
from markupsafe import escape
import sqlite3
import re  # For regex pattern matching
import requests  # For sending data to the dashboard
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DASHBOARD_URL = "http://dashboard:5001/report-attack"  # The dashboard URL to send attack info

# Function to create a SQLite database for users
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)')
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    c.execute("INSERT INTO users (username, password) VALUES ('user1', 'password1')")
        # Patients table
    c.execute('''CREATE TABLE IF NOT EXISTS patients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    age INTEGER,
                    diagnosis TEXT,
                    last_visit DATE)''')
    # Appointments table
    c.execute('''CREATE TABLE IF NOT EXISTS appointments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patient_name TEXT,
                    date TEXT,
                    time TEXT,
                    reason TEXT)''')
    conn.commit()
    conn.close()

# Function to send attack info to the dashboard
def report_attack(attack_type):
    try:
        data = {
            'type': attack_type,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        print(f"Reporting {attack_type} attack to dashboard with data: {data}")  # Debug output
        response = requests.post(DASHBOARD_URL, json=data)
        print(f"Dashboard response: {response.status_code}, {response.text}")  # Debug output
    except Exception as e:
        print(f"Error reporting attack: {e}")


@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')

    # Fetch data for patients and appointments
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM patients")
    patients = c.fetchall()
    c.execute("SELECT * FROM appointments ORDER BY date, time")
    appointments = c.fetchall()
    conn.close()

    return render_template('dashboard.html', patients=patients, appointments=appointments)

# Add Patient route
@app.route('/add_patient', methods=['POST'])
def add_patient():
    if 'username' not in session:
        return redirect('/login')
    
    name = request.form['name']
    age = request.form['age']
    diagnosis = request.form['diagnosis']
    last_visit = request.form['last_visit']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO patients (name, age, diagnosis, last_visit) VALUES (?, ?, ?, ?)", 
              (name, age, diagnosis, last_visit))
    conn.commit()
    conn.close()
    
    flash('Patient added successfully!')
    return redirect('/dashboard')

# Add Appointment route
@app.route('/add_appointment', methods=['POST'])
def add_appointment():
    if 'username' not in session:
        return redirect('/login')
    
    patient_name = request.form['patient_name']
    date = request.form['date']
    time = request.form['time']
    reason = request.form['reason']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO appointments (patient_name, date, time, reason) VALUES (?, ?, ?, ?)", 
              (patient_name, date, time, reason))
    conn.commit()
    conn.close()
    
    flash('Appointment added successfully!')
    return redirect('/dashboard')

# Vulnerable Login Route (SQL Injection and XSS Detection)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # XSS Attack Detection: Detect <script> or other dangerous HTML tags
        xss_pattern = re.compile(r"<.*?>", re.IGNORECASE)
        if xss_pattern.search(username):
            # If script tags or HTML are detected in the username
            report_attack("XSS")
            return f"""
            <script>alert('XSS Attack Detected!');</script>
            <p>Please try again. Stay safe!</p>
            <a href="/login">Go back to Login</a>
            """

        # SQL Injection Detection Logic: Detect common SQL injection patterns
        sql_injection_patterns = [
            r"(\bor\b|\band\b)\s+\d+=\d+",   # Detect patterns like `OR 1=1` or `AND 1=1`
            r"'\s*--",                       # Detect `' --` comments
            r"' OR .+=",                     # Detect `' OR something=something`
            r"';",                           # Detect ending statements with semicolons
        ]
        for pattern in sql_injection_patterns:
            if re.search(pattern, username, re.IGNORECASE):
                report_attack("SQL Injection")
                break

        # SQL Vulnerability: Building SQL query without parameterization
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            c.execute(query)
            user = c.fetchone()

            if user:
                session['username'] = username
                return redirect('/')
            else:
                # Invalid login, but report potential SQL injection attack
                if "OR" in username or "'" in username:
                    report_attack("SQL Injection")
                
                return f'<p>Invalid login. Try again. Username entered: {escape(username)}</p>'
        except sqlite3.OperationalError as e:
            # Detect SQL Injection and report it
            report_attack("SQL Injection")
            return f'<p>SQL Error: {escape(str(e))}</p><p>Input was: {escape(username)}</p>'

    return render_template('login.html')

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect('/login')

# Initialize database on startup
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
