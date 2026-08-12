import sqlite3

connection = sqlite3.connect(
    r"instance\socsentinel.db"
)

tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

print("Tables in database:")

for table in tables:
    print("-", table[0])

connection.close()