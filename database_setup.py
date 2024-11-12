import sqlite3
import os

# Define the path to the database file
db_path = '/persistent/database.db'

# Ensure the directory exists
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# Print the absolute path for debugging
print(f"Database file path: {os.path.abspath(db_path)}")

# Connect to the database
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Create tables as before
cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')
print("Table 'users' created successfully.")

cur.execute('''
CREATE TABLE IF NOT EXISTS system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_status TEXT,
    ml_detection_status TEXT,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')
print("Table 'system_status' created successfully.")

cur.execute('''
CREATE TABLE IF NOT EXISTS attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')
print("Table 'attack_logs' created successfully.")

cur.execute('''
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    age INTEGER,
    condition TEXT
)
''')
print("Table 'patients' created successfully.")

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
print("Table 'appointments' created successfully.")

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database setup completed.")
