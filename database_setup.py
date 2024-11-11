import sqlite3
import os

# Define the path for the shared SQLite database
db_path = '/persistent/database.db'

# Check if the database file already exists
db_exists = os.path.exists(db_path)

# Connect to the SQLite database
conn = sqlite3.connect(db_path)
cur = conn.cursor()

if not db_exists:
    print("Creating database and tables...")
else:
    print("Database already exists, ensuring tables are set up...")

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
