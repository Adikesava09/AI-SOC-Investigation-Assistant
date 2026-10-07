import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer


DB_NAME = "database/soc.db"


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


def create_dashboard():

    alerts = get_alerts()

    total = len(alerts)

    critical = sum(
        1 for a in alerts
        if a[5] == "CRITICAL"
    )

    high = sum(
        1 for a in alerts
        if a[5] == "HIGH"
    )

    medium = sum(
        1 for a in alerts
        if a[5] == "MEDIUM"
    )

    open_alerts = sum(
        1 for a in alerts
        if a[7] == "Open"
    )

    investigating = sum(
        1 for a in alerts
        if a[7] == "Investigating"
    )

    resolved = sum(
        1 for a in alerts
        if a[7] == "Resolved"
    )

    rows = ""

    for alert in alerts:

        rows += f"""
        <tr>
            <td>{alert[0]}</td>
            <td>{alert[1]}</td>
            <td>{alert[2]}</td>
            <td>{alert[3]}</td>
            <td>{alert[4]}</td>
            <td>{alert[5]}</td>
            <td>{alert[6]}</td>
            <td>{alert[7]}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>AI SOC Investigation Dashboard</title>

        <meta charset="UTF-8">

        <style>

            body {{
                font-family: Arial, sans-serif;
                background: #111827;
                color: white;
                margin: 30px;
            }}

            h1 {{
                text-align: center;
                margin-bottom: 30px;
            }}

            .cards {{
                display: grid;
                grid-template-columns:
                repeat(4, 1fr);
                gap: 15px;
                margin-bottom: 30px;
            }}

            .card {{
                background: #1f2937;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
            }}

            .number {{
                font-size: 30px;
                font-weight: bold;
                margin-top: 10px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                background: #1f2937;
            }}

            th {{
                background: #374151;
                padding: 12px;
            }}

            td {{
                padding: 12px;
                border: 1px solid #374151;
            }}

            tr:hover {{
                background: #273449;
            }}

        </style>

    </head>


    <body>

        <h1>
            AI SOC Investigation Dashboard
        </h1>


        <div class="cards">

            <div class="card">
                <div>Total Alerts</div>
                <div class="number">{total}</div>
            </div>


            <div class="card">
                <div>Critical</div>
                <div class="number">{critical}</div>
            </div>


            <div class="card">
                <div>High</div>
                <div class="number">{high}</div>
            </div>


            <div class="card">
                <div>Medium</div>
                <div class="number">{medium}</div>
            </div>


            <div class="card">
                <div>Open</div>
                <div class="number">{open_alerts}</div>
            </div>


            <div class="card">
                <div>Investigating</div>
                <div class="number">{investigating}</div>
            </div>


            <div class="card">
                <div>Resolved</div>
                <div class="number">{resolved}</div>
            </div>

        </div>


        <table>

            <tr>

                <th>ID</th>
                <th>Alert</th>
                <th>Type</th>
                <th>MITRE</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>IOC</th>
                <th>Status</th>

            </tr>

            {rows}

        </table>

    </body>

    </html>
    """


class SOCHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        html = create_dashboard()

        self.send_response(200)

        self.send_header(
            "Content-type",
            "text/html"
        )

        self.end_headers()

        self.wfile.write(
            html.encode("utf-8")
        )


server = HTTPServer(
    ("localhost", 8000),
    SOCHandler
)


print("================================")
print("       AI SOC DASHBOARD")
print("================================")
print("Dashboard running at:")
print("http://localhost:8000")
print("Press CTRL+C to stop.")


server.serve_forever()