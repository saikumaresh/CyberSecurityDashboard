import sqlite3
import os

# Define the path to the database file
db_path = '/persistent/dashboard.db'

# Ensure the directory exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# Connect to the database
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Create users table for authentication (if required by the application)
cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')

# Create system_status table (for dashboard)
cur.execute('''
CREATE TABLE IF NOT EXISTS system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_status TEXT,
    ml_detection_status TEXT,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create attack_logs table (for dashboard)
cur.execute('''
CREATE TABLE IF NOT EXISTS attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create patients table (for vulnerable-site)
cur.execute('''
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    age INTEGER,
    condition TEXT
)
''')

# Create appointments table (for vulnerable-site)
cur.execute('''
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    date TEXT,
    time TEXT,
    description TEXT,
    FOREIGN KEY(patient_id) REFERENCES patients(id)
)
''')

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database setup completed.")
