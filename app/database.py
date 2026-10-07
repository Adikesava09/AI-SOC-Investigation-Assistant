import sqlite3

DB_NAME = "database/soc.db"


def create_database():
    connection = sqlite3.connect(DB_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            alert TEXT,
            alert_type TEXT,
            mitre TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            ioc TEXT,
            status TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("SOC database created successfully!")


if __name__ == "__main__":
    create_database()