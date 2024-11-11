import sqlite3

# Connect to the shared database file
conn = sqlite3.connect('/persistent/database.db')
cur = conn.cursor()

# Create system_status table (used by dashboard)
cur.execute('''
CREATE TABLE IF NOT EXISTS system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_status TEXT,
    ml_detection_status TEXT,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create attack_logs table (used by dashboard)
cur.execute('''
CREATE TABLE IF NOT EXISTS attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create patients table (used by vulnerable-site)
cur.execute('''
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    age INTEGER,
    condition TEXT
)
''')

# Create appointments table (used by vulnerable-site)
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
