import os
import sqlite3
from datetime import datetime
from config.config import Config

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

class DatabaseManager:
    """
    Database persistence manager supporting MySQL with automatic SQLite fallback
    for zero-downtime local demonstration.
    """

    def __init__(self):
        self.use_mysql = False
        self.sqlite_db_path = os.path.join(Config.BASE_DIR, "database", "dark_pattern_local.db")
        self.init_db()

    def _get_mysql_connection(self, create_db_if_missing=True):
        if not MYSQL_AVAILABLE:
            return None
        try:
            # First connect without DB specified to ensure DB exists
            conn = mysql.connector.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
                connection_timeout=3
            )
            if create_db_if_missing:
                cursor = conn.cursor()
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {Config.DB_NAME}")
                cursor.close()
                conn.database = Config.DB_NAME
            return conn
        except Exception as e:
            # print(f"[Database Warning] MySQL connection failed: {e}")
            return None

    def _get_sqlite_connection(self):
        os.makedirs(os.path.dirname(self.sqlite_db_path), exist_ok=True)
        conn = sqlite3.connect(self.sqlite_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes database schema for scans and detections tables."""
        # Try MySQL initialization
        mysql_conn = self._get_mysql_connection(create_db_if_missing=True)
        if mysql_conn:
            try:
                cursor = mysql_conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        url TEXT NOT NULL,
                        scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                        total_elements INT NOT NULL DEFAULT 0,
                        total_detections INT NOT NULL DEFAULT 0
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detections (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        scan_id INT NOT NULL,
                        pattern VARCHAR(100) NOT NULL,
                        element_type VARCHAR(100),
                        element_text TEXT,
                        confidence FLOAT,
                        severity VARCHAR(50),
                        source VARCHAR(50),
                        explanation TEXT,
                        html_snippet TEXT,
                        screenshot_path VARCHAR(255),
                        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    )
                """)
                mysql_conn.commit()
                cursor.close()
                mysql_conn.close()
                self.use_mysql = True
                print("[Database] Successfully connected to MySQL database.")
                return
            except Exception as e:
                print(f"[Database Warning] MySQL schema init failed: {e}. Falling back to SQLite.")

        # Fallback to SQLite
        self.use_mysql = False
        sqlite_conn = self._get_sqlite_connection()
        cursor = sqlite_conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_elements INTEGER NOT NULL DEFAULT 0,
                total_detections INTEGER NOT NULL DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                pattern TEXT NOT NULL,
                element_type TEXT,
                element_text TEXT,
                confidence REAL,
                severity TEXT,
                source TEXT,
                explanation TEXT,
                html_snippet TEXT,
                screenshot_path TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        sqlite_conn.commit()
        sqlite_conn.close()
        print("[Database] Initialized SQLite persistent database.")

    def save_scan(self, url, total_elements, total_detections, detections):
        """Saves scan metadata and associated detections. Returns new scan_id."""
        scan_date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO scans (url, scan_date, total_elements, total_detections) VALUES (%s, %s, %s, %s)",
                        (url, scan_date_str, total_elements, total_detections)
                    )
                    scan_id = cursor.lastrowid

                    for d in detections:
                        cursor.execute("""
                            INSERT INTO detections
                            (scan_id, pattern, element_type, element_text, confidence, severity, source, explanation, html_snippet, screenshot_path)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            scan_id, d.get("pattern"), d.get("element_type"), d.get("element_text"),
                            d.get("confidence"), d.get("severity"), d.get("source"),
                            d.get("explanation"), d.get("html_snippet"), d.get("screenshot_path")
                        ))

                    conn.commit()
                    cursor.close()
                    conn.close()
                    return scan_id
                except Exception as e:
                    print(f"[Database Error] MySQL save_scan failed: {e}")

        # SQLite fallback execution
        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (url, scan_date, total_elements, total_detections) VALUES (?, ?, ?, ?)",
            (url, scan_date_str, total_elements, total_detections)
        )
        scan_id = cursor.lastrowid

        for d in detections:
            cursor.execute("""
                INSERT INTO detections
                (scan_id, pattern, element_type, element_text, confidence, severity, source, explanation, html_snippet, screenshot_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, d.get("pattern"), d.get("element_type"), d.get("element_text"),
                d.get("confidence"), d.get("severity"), d.get("source"),
                d.get("explanation"), d.get("html_snippet"), d.get("screenshot_path")
            ))

        conn.commit()
        conn.close()
        return scan_id

    def get_scan(self, scan_id):
        """Retrieves scan record and associated detections by scan_id."""
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
                    scan = cursor.fetchone()
                    if scan:
                        cursor.execute("SELECT * FROM detections WHERE scan_id = %s", (scan_id,))
                        scan["detections"] = cursor.fetchall()
                        cursor.close()
                        conn.close()
                        return scan
                except Exception as e:
                    print(f"[Database Error] MySQL get_scan failed: {e}")

        # SQLite fallback execution
        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        if not scan_row:
            conn.close()
            return None

        scan = dict(scan_row)
        cursor.execute("SELECT * FROM detections WHERE scan_id = ?", (scan_id,))
        scan["detections"] = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return scan

    def get_all_scans(self):
        """Retrieves summary list of all scans ordered by newest first."""
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM scans ORDER BY id DESC")
                    scans = cursor.fetchall()
                    cursor.close()
                    conn.close()
                    return scans
                except Exception as e:
                    print(f"[Database Error] MySQL get_all_scans failed: {e}")

        # SQLite fallback execution
        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC")
        scans = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return scans
