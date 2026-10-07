import sqlite3

DB_NAME = "database/soc.db"


def save_alert(alert_id, alert, alert_type, mitre, risk_score, risk_level, ioc):

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO alerts
        (id, alert, alert_type, mitre, risk_score, risk_level, ioc, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        alert,
        alert_type,
        mitre,
        risk_score,
        risk_level,
        ioc,
        "Open"
    ))

    connection.commit()
    connection.close()


def get_alerts():

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, alert, alert_type, mitre,
               risk_score, risk_level, ioc, status
        FROM alerts
        ORDER BY risk_score DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


def update_status(alert_id, status):

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (status, alert_id))

    connection.commit()
    connection.close()