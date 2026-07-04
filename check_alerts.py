import sqlite3, json
conn = sqlite3.connect('D:/graud_x/guardian/guardian.db')
c = conn.cursor()
c.execute("SELECT id, type, process_name, severity, summary FROM alerts WHERE type IN ('CAMERA_ACCESS', 'MIC_ACCESS') ORDER BY id DESC LIMIT 5")
for r in c.fetchall():
    print(r)
conn.close()
