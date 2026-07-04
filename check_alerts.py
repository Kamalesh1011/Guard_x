import sqlite3, json

conn = sqlite3.connect('D:/graud_x/guardian/guardian.db')
c = conn.cursor()
c.execute("SELECT id, type, severity, summary, risk_factors, mitre_ttps, recommendation FROM alerts WHERE type='CAMERA_ACCESS' ORDER BY id DESC LIMIT 1")
row = c.fetchone()

if row:
    print(f"{'='*80}")
    print(f"ID: {row[0]} | Type: {row[1]} | Severity: {row[2]}")
    print(f"\nSummary: {row[3]}")
    
    rf = json.loads(row[4]) if row[4] else []
    print(f"\nRisk Factors ({len(rf)}):")
    for r in rf[:5]:
        print(f"  [{r.get('risk_level','')}] {r.get('factor','')}")
        print(f"    {r.get('detail','')}")
        print(f"    MITRE: {r.get('ttp','')}")
    
    mitre = json.loads(row[5]) if row[5] else []
    print(f"\nMITRE ATT&CK: {', '.join(mitre[:3])}")
    print(f"\nRecommendation: {row[6]}")
else:
    print("No camera alerts found")

conn.close()
