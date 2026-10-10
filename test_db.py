from app.database.connection import check_database_connection

if check_database_connection():
    print("SUCCESS: CyberGuard connected to PostgreSQL!")
else:
    print("FAILED: Could not connect to PostgreSQL.")
