import sqlite3

# Create or connect to the SQLite database
conn = sqlite3.connect('/persistent/dashboard.db')

# Create a cursor
cur = conn.cursor()

# Create table for system status
cur.execute('''
CREATE TABLE IF NOT EXISTS system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_status TEXT,
    ml_detection_status TEXT,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Create table for attack logs
cur.execute('''
CREATE TABLE IF NOT EXISTS attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Commit and close the connection
conn.commit()
conn.close()

print("Database setup completed.")
