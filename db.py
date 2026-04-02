"""
Database module — PostgreSQL storage for analysis results.
"""

import json
import os
import psycopg2
from psycopg2.extras import Json


DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", "5432")),
    "dbname":   os.getenv("DB_NAME",     "traffic_analyzer"),
    "user":     os.getenv("DB_USER",     "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS analyses (
    id            SERIAL PRIMARY KEY,
    filename      TEXT        NOT NULL,
    analyzed_at   TIMESTAMPTZ NOT NULL,
    total_packets INTEGER     NOT NULL,
    protocols     JSONB,
    top_src_ips   JSONB,
    top_dst_ips   JSONB,
    top_ports     JSONB,
    anomalies     JSONB,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS anomalies (
    id          SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id) ON DELETE CASCADE,
    type        TEXT,
    severity    TEXT,
    src_ip      TEXT,
    detail      TEXT,
    detected_at TIMESTAMPTZ NOT NULL
);
"""


class Database:
    def __init__(self):
        self.conn = psycopg2.connect(**DB_CONFIG)
        self.conn.autocommit = False
        self._ensure_tables()

    def _ensure_tables(self):
        with self.conn.cursor() as cur:
            cur.execute(CREATE_TABLE_SQL)
        self.conn.commit()

    def save_analysis(self, result: dict) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO analyses
                    (filename, analyzed_at, total_packets, protocols,
                     top_src_ips, top_dst_ips, top_ports, anomalies)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    result["file"],
                    result["analyzed_at"],
                    result["total_packets"],
                    Json(result["protocols"]),
                    Json(result["top_src_ips"]),
                    Json(result["top_dst_ips"]),
                    Json(result["top_ports"]),
                    Json(result["anomalies"]),
                ),
            )
            analysis_id = cur.fetchone()[0]

            # Store individual anomalies for easy querying
            for anomaly in result["anomalies"]:
                cur.execute(
                    """
                    INSERT INTO anomalies
                        (analysis_id, type, severity, src_ip, detail, detected_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        analysis_id,
                        anomaly["type"],
                        anomaly["severity"],
                        anomaly["src_ip"],
                        anomaly["detail"],
                        result["analyzed_at"],
                    ),
                )

        self.conn.commit()
        return analysis_id

    def get_all_analyses(self) -> list:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT id, filename, analyzed_at, total_packets FROM analyses ORDER BY created_at DESC"
            )
            return cur.fetchall()

    def get_high_severity_anomalies(self) -> list:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.filename, an.type, an.src_ip, an.detail, an.detected_at
                FROM anomalies an
                JOIN analyses a ON a.id = an.analysis_id
                WHERE an.severity = 'HIGH'
                ORDER BY an.detected_at DESC
                """
            )
            return cur.fetchall()

    def close(self):
        self.conn.close()
