import sqlite3

# Connect to the SQLite database (make sure the path matches the one used in app.py)
conn = sqlite3.connect('database.db')  # Adjust path if needed
c = conn.cursor()

# Drop the existing tables (if they exist) to apply schema changes
c.execute('DROP TABLE IF EXISTS patients')
c.execute('DROP TABLE IF EXISTS appointments')

# Re-create the patients table with the updated schema
c.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        age INTEGER,
        diagnosis TEXT,
        last_visit TEXT
    )
''')

# Re-create the appointments table with the necessary columns
c.execute('''
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_name TEXT,     -- Added patient_name column
        date TEXT,
        time TEXT,
        reason TEXT            -- Updated to match the add_appointment function
    )
''')

# Commit the changes and close the connection
conn.commit()
conn.close()
