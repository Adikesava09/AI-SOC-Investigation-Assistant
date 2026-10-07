import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


DB_NAME = "database/soc.db"


def get_alerts(search="", risk="", status=""):

    connection = sqlite3.connect(DB_NAME)

    cursor = connection.cursor()

    query = """
        SELECT id, alert, alert_type, mitre,
               risk_score, risk_level, ioc, status
        FROM alerts
        WHERE 1=1
    """

    parameters = []

    if search:

        query += " AND alert LIKE ?"

        parameters.append(
            f"%{search}%"
        )

    if risk:

        query += " AND risk_level = ?"

        parameters.append(risk)

    if status:

        query += " AND status = ?"

        parameters.append(status)

    query += " ORDER BY risk_score DESC"

    cursor.execute(
        query,
        parameters
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts


def create_dashboard(
    search="",
    risk="",
    status=""
):

    alerts = get_alerts(
        search,
        risk,
        status
    )

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
    font-family: Arial;
    background: #111827;
    color: white;
    margin: 30px;
}}

h1 {{
    text-align: center;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin: 25px 0;
}}

.card {{
    background: #1f2937;
    padding: 20px;
    border-radius: 10px;
    text-align: center;
}}

.number {{
    font-size: 28px;
    font-weight: bold;
    margin-top: 8px;
}}

.filters {{
    background: #1f2937;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 20px;
}}

input, select, button {{
    padding: 10px;
    margin: 5px;
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

</style>

</head>


<body>

<h1>AI SOC Investigation Dashboard</h1>


<div class="filters">

<form method="GET">

<input
type="text"
name="search"
placeholder="Search alert..."
value="{search}"
>


<select name="risk">

<option value="">All Risk</option>

<option value="CRITICAL">
Critical
</option>

<option value="HIGH">
High
</option>

<option value="MEDIUM">
Medium
</option>

<option value="LOW">
Low
</option>

</select>


<select name="status">

<option value="">
All Status
</option>

<option value="Open">
Open
</option>

<option value="Investigating">
Investigating
</option>

<option value="Resolved">
Resolved
</option>

</select>


<button type="submit">
Filter
</button>

</form>

</div>


<div class="cards">

<div class="card">
Total Alerts
<div class="number">
{total}
</div>
</div>


<div class="card">
Critical
<div class="number">
{critical}
</div>
</div>


<div class="card">
High
<div class="number">
{high}
</div>
</div>


<div class="card">
Medium
<div class="number">
{medium}
</div>
</div>


<div class="card">
Open
<div class="number">
{open_alerts}
</div>
</div>


<div class="card">
Investigating
<div class="number">
{investigating}
</div>
</div>


<div class="card">
Resolved
<div class="number">
{resolved}
</div>
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


class SOCHandler(
    BaseHTTPRequestHandler
):

    def do_GET(self):

        parsed = urlparse(
            self.path
        )

        parameters = parse_qs(
            parsed.query
        )

        search = parameters.get(
            "search",
            [""]
        )[0]

        risk = parameters.get(
            "risk",
            [""]
        )[0]

        status = parameters.get(
            "status",
            [""]
        )[0]

        html = create_dashboard(
            search,
            risk,
            status
        )

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
print("http://localhost:8000")
print("Press CTRL+C to stop.")


server.serve_forever()