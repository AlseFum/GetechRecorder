import psycopg2
from psycopg2.extras import DictCursor
import os
import sys
import signal
import time

# 全局数据库连接
conn = None

def get_db_connection():
    """获取数据库连接"""
    global conn
    try:
        if conn is None or conn.closed:
            conn = psycopg2.connect(
                host="localhost",
                port="5432",
                dbname="testdb",
                user="postgres",
                password="114514"
            )
            # 设置自动提交模式
            conn.autocommit = True
        return conn
    except Exception as e:
        print(f"数据库连接失败: {str(e)}")
        # 如果连接失败，等待后重试
        time.sleep(1)
        return get_db_connection()

def restart_server():
    """重启 uvicorn 服务器"""
    try:
        # 获取当前进程的父进程 ID
        parent_pid = os.getppid()
        # 发送 SIGTERM 信号给父进程
        os.kill(parent_pid, signal.SIGTERM)
        print("服务器重启中...")
    except Exception as e:
        print(f"重启失败: {str(e)}")

def init_db():
    """初始化数据库表"""
    global conn
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 创建用户表
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(50) PRIMARY KEY,
                salt BYTEA NOT NULL,
                password_hash BYTEA NOT NULL
            );
        """)
        
        cur.close()
    except Exception as e:
        print(f"初始化数据库失败: {str(e)}")
        # 如果失败，尝试重新连接并重试
        conn = None
        init_db()

def store_user(username: str, salt: bytes, password_hash: bytes) -> bool:
    """存储用户信息到数据库"""
    global conn
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 使用 ON CONFLICT 处理重复用户名
        cur.execute("""
            INSERT INTO users (username, salt, password_hash)
            VALUES (%s, %s, %s)
            ON CONFLICT (username) 
            DO UPDATE SET salt = EXCLUDED.salt, password_hash = EXCLUDED.password_hash
        """, (username, salt, password_hash))
        
        cur.close()
        return True
    except Exception as e:
        print(f"存储用户失败: {str(e)}")
        # 如果失败，尝试重新连接并重试
        conn = None
        return store_user(username, salt, password_hash)

def get_user(username: str) -> tuple[bytes | None, bytes | None]:
    """从数据库获取用户信息"""
    global conn
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=DictCursor)
        
        cur.execute(
            "SELECT salt, password_hash FROM users WHERE username = %s",
            (username,)
        )
        result = cur.fetchone()
        cur.close()
        
        if result:
            return result['salt'], result['password_hash']
        return None, None
    except Exception as e:
        print(f"获取用户失败: {str(e)}")
        # 如果失败，尝试重新连接并重试
        conn = None
        return get_user(username)

# 初始化数据库
if __name__ == "__main__":
    init_db()
    # 如果需要重启服务器，取消下面的注释
    # restart_server()