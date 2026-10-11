"""Small connection-pool wrapper around mysql-connector-python."""
import mysql.connector
from mysql.connector import pooling
from config import Config

_pool = None


def get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="netguard_pool",
            pool_size=5,
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DATABASE,
        )
    return _pool


def get_conn():
    return get_pool().get_connection()


def query(sql, params=None, fetch=True, many=False):
    conn = get_conn()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params or ())
        if fetch:
            rows = cur.fetchall()
        else:
            rows = None
        if not sql.strip().upper().startswith("SELECT"):
            conn.commit()
        last_id = cur.lastrowid
        cur.close()
        return rows if fetch else last_id
    finally:
        conn.close()


def executemany(sql, seq_of_params):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.executemany(sql, seq_of_params)
        conn.commit()
        cur.close()
    finally:
        conn.close()
