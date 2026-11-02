import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "nids.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            protocol TEXT,
            packets INTEGER,
            bytes INTEGER,
            prediction TEXT,
            confidence REAL,
            detection_type TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_alert(timestamp, source_ip, source_port, destination_ip,
                  destination_port, protocol, packets, bytes_count,
                  prediction, confidence, detection_type="ML"):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp, source_ip, source_port, destination_ip,
            destination_port, protocol, packets, bytes,
            prediction, confidence, detection_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp, source_ip, source_port, destination_ip,
        destination_port, protocol, packets, bytes_count,
        prediction, confidence, detection_type
    ))

    conn.commit()
    conn.close()


def get_recent_alerts(limit=50, include_simulation: bool = False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    where_clause = "" if include_simulation else "WHERE COALESCE(detection_type, '') != 'SIMULATION'"

    cursor.execute(f"""
        SELECT * FROM alerts
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_stats(include_simulation: bool = False):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    sim_filter = "" if include_simulation else "WHERE COALESCE(detection_type, '') != 'SIMULATION'"

    cursor.execute(f"SELECT COUNT(*) FROM alerts {sim_filter}")
    total = cursor.fetchone()[0]

    cursor.execute(f"""
        SELECT prediction, COUNT(*)
        FROM alerts
        {sim_filter}
        GROUP BY prediction
    """)
    counts_by_type = dict(cursor.fetchall())

    cursor.execute(f"SELECT COALESCE(SUM(packets), 0), COALESCE(SUM(bytes), 0) FROM alerts {sim_filter}")
    sum_packets, sum_bytes = cursor.fetchone()

    conn.close()

    return {
        "total_flows": total,
        "counts_by_type": counts_by_type,
        "total_packets": sum_packets,
        "total_bytes": sum_bytes
    }


def get_flows(limit=100, offset=0, protocol=None, search=None, threats_only=False, include_simulation: bool = False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    conditions = []
    params = []

    if not include_simulation:
        conditions.append("COALESCE(detection_type, '') != 'SIMULATION'")

    if threats_only:
        conditions.append("prediction != 'BENIGN'")

    if protocol and protocol.upper() != "ALL":
        conditions.append("UPPER(protocol) = ?")
        params.append(protocol.upper())

    if search:
        s = f"%{search.strip().lower()}%"
        conditions.append("(LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR CAST(source_port AS TEXT) LIKE ? OR CAST(destination_port AS TEXT) LIKE ?)")
        params.extend([s, s, s, s])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    # Get total matching count
    cursor.execute(f"SELECT COUNT(*) FROM alerts {where_clause}", params)
    total_matching = cursor.fetchone()[0]

    # Fetch rows
    query_params = list(params)
    query_params.extend([limit, offset])
    cursor.execute(f"""
        SELECT * FROM alerts
        {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, query_params)

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "total": total_matching,
        "items": rows
    }


def get_flow_by_id(flow_id: int, include_simulation: bool = False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts WHERE id = ?", (flow_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None
    record = dict(row)
    if not include_simulation and (record.get("detection_type") or "").upper() == "SIMULATION":
        return None
    return record


def get_traffic_summary(include_simulation: bool = False):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    sim_filter = "" if include_simulation else "WHERE COALESCE(detection_type, '') != 'SIMULATION'"

    cursor.execute(f"""
        SELECT 
            COUNT(*) as total_flows,
            COALESCE(SUM(packets), 0) as total_packets,
            COALESCE(SUM(bytes), 0) as total_bytes,
            SUM(CASE WHEN UPPER(protocol) = 'TCP' THEN 1 ELSE 0 END) as tcp_count,
            SUM(CASE WHEN UPPER(protocol) = 'UDP' THEN 1 ELSE 0 END) as udp_count,
            SUM(CASE WHEN UPPER(protocol) NOT IN ('TCP', 'UDP') THEN 1 ELSE 0 END) as other_count
        FROM alerts
        {sim_filter}
    """)
    row = cursor.fetchone()
    conn.close()

    return {
        "total_flows": row[0] or 0,
        "total_packets": row[1] or 0,
        "total_bytes": row[2] or 0,
        "tcp_count": row[3] or 0,
        "udp_count": row[4] or 0,
        "other_count": row[5] or 0
    }