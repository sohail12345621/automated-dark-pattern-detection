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
    Handles Scans, Detections, User Authentication, and Security Audit Logging.
    """

    def __init__(self):
        self.use_mysql = False
        self.sqlite_db_path = os.path.join(Config.BASE_DIR, "database", "dark_pattern_local.db")
        self.init_db()

    def _get_mysql_connection(self, create_db_if_missing=True):
        if not MYSQL_AVAILABLE:
            return None
        try:
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
        except Exception:
            return None

    def _get_sqlite_connection(self):
        os.makedirs(os.path.dirname(self.sqlite_db_path), exist_ok=True)
        conn = sqlite3.connect(self.sqlite_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initializes database schema for scans, detections, users, and audit_logs tables."""
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
                        finding_id VARCHAR(50),
                        pattern VARCHAR(100) NOT NULL,
                        element_type VARCHAR(100),
                        element_text TEXT,
                        confidence FLOAT,
                        severity VARCHAR(50),
                        source VARCHAR(50),
                        explanation TEXT,
                        privacy_security_relevance TEXT,
                        recommendation TEXT,
                        html_snippet TEXT,
                        screenshot_path VARCHAR(255),
                        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(100) UNIQUE NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role VARCHAR(20) NOT NULL DEFAULT 'USER',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT,
                        username VARCHAR(100),
                        action VARCHAR(50) NOT NULL,
                        status VARCHAR(20) DEFAULT 'SUCCESS',
                        ip_address VARCHAR(45),
                        details TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
                finding_id TEXT,
                pattern TEXT NOT NULL,
                element_type TEXT,
                element_text TEXT,
                confidence REAL,
                severity TEXT,
                source TEXT,
                explanation TEXT,
                privacy_security_relevance TEXT,
                recommendation TEXT,
                html_snippet TEXT,
                screenshot_path TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'USER',
                created_at TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                status TEXT DEFAULT 'SUCCESS',
                ip_address TEXT,
                details TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        sqlite_conn.commit()
        sqlite_conn.close()
        print("[Database] Initialized SQLite persistent database.")

    # --- SCAN & DETECTION METHODS ---
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
                            (scan_id, finding_id, pattern, element_type, element_text, confidence, severity, source, explanation, privacy_security_relevance, recommendation, html_snippet, screenshot_path)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            scan_id, d.get("finding_id"), d.get("pattern"), d.get("element_type"), d.get("element_text"),
                            d.get("confidence"), d.get("severity"), d.get("source"),
                            d.get("explanation"), d.get("privacy_security_relevance"), d.get("recommendation"),
                            d.get("html_snippet"), d.get("screenshot_path")
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
                (scan_id, finding_id, pattern, element_type, element_text, confidence, severity, source, explanation, privacy_security_relevance, recommendation, html_snippet, screenshot_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, d.get("finding_id"), d.get("pattern"), d.get("element_type"), d.get("element_text"),
                d.get("confidence"), d.get("severity"), d.get("source"),
                d.get("explanation"), d.get("privacy_security_relevance"), d.get("recommendation"),
                d.get("html_snippet"), d.get("screenshot_path")
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

    # --- USER AUTHENTICATION METHODS ---
    def create_user(self, username, email, password_hash, role="USER"):
        """Creates a new user account. Returns new user_id."""
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                        (username, email, password_hash, role, created_at)
                    )
                    user_id = cursor.lastrowid
                    conn.commit()
                    cursor.close()
                    conn.close()
                    return user_id
                except Exception as e:
                    print(f"[Database Error] MySQL create_user failed: {e}")
                    return None

        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, email, password_hash, role, created_at)
            )
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            conn.close()
            return None

    def get_user_by_username(self, username):
        """Retrieves user by username."""
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                    user = cursor.fetchone()
                    cursor.close()
                    conn.close()
                    return user
                except Exception as e:
                    print(f"[Database Error] MySQL get_user_by_username failed: {e}")

        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_users(self):
        """Retrieves list of all users (for admin audit view)."""
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id ASC")
                    users = cursor.fetchall()
                    cursor.close()
                    conn.close()
                    return users
                except Exception as e:
                    print(f"[Database Error] MySQL get_all_users failed: {e}")

        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id ASC")
        users = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return users

    # --- SECURITY AUDIT LOGGING METHODS ---
    def log_audit_event(self, user_id, username, action, status="SUCCESS", ip_address="127.0.0.1", details=None):
        """Records a security audit event."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO audit_logs (user_id, username, action, status, ip_address, details, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (user_id, username, action, status, ip_address, details, timestamp)
                    )
                    conn.commit()
                    cursor.close()
                    conn.close()
                    return
                except Exception as e:
                    print(f"[Database Error] MySQL log_audit_event failed: {e}")

        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (user_id, username, action, status, ip_address, details, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, username, action, status, ip_address, details, timestamp)
        )
        conn.commit()
        conn.close()

    def get_audit_logs(self, limit=100):
        """Retrieves audit logs ordered by newest first."""
        if self.use_mysql:
            conn = self._get_mysql_connection()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT %s", (limit,))
                    logs = cursor.fetchall()
                    cursor.close()
                    conn.close()
                    return logs
                except Exception as e:
                    print(f"[Database Error] MySQL get_audit_logs failed: {e}")

        conn = self._get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
        logs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return logs
