import sqlite3
import json
from pathlib import Path
import logging

class Database:
    def __init__(self, db_path='strike_force.db'):
        self.db_path = Path(db_path)
        self.init_db()
    
    def get_connection(self):
        """Create a database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create crypto_keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crypto_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hex TEXT NOT NULL,
                    iv_hex TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create bots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bots (
                    name TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create backups table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS backups (
                    serial TEXT PRIMARY KEY,
                    bot_name TEXT NOT NULL,
                    parent_serial TEXT DEFAULT '-',
                    created_at INTEGER,
                    password TEXT,
                    FOREIGN KEY (bot_name) REFERENCES bots (name) ON DELETE CASCADE
                )
            ''')
            
            # Create branches table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS branches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_serial TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (backup_serial) REFERENCES backups (serial) ON DELETE CASCADE,
                    UNIQUE(backup_serial, epoch, password_hash)
                )
            ''')
            
            conn.commit()
    
    # ====================== Crypto Methods ======================
    def get_crypto_keys(self):
        """Get the latest crypto keys"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT key_hex, iv_hex FROM crypto_keys ORDER BY id DESC LIMIT 1')
            row = cursor.fetchone()
            return (bytes.fromhex(row['key_hex']), bytes.fromhex(row['iv_hex'])) if row else (None, None)
    
    def set_crypto_keys(self, key_hex, iv_hex):
        """Set new crypto keys"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO crypto_keys (key_hex, iv_hex) VALUES (?, ?)',
                (key_hex, iv_hex)
            )
            conn.commit()
            return cursor.lastrowid
    
    # ====================== Bot Methods ======================
    def add_bot(self, bot_name):
        """Add a new bot"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO bots (name) VALUES (?)', (bot_name,))
            conn.commit()
            return cursor.rowcount > 0
    
    def delete_bot(self, bot_name):
        """Delete a bot and all its backups"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM bots WHERE name = ?', (bot_name,))
            conn.commit()
            return cursor.rowcount > 0
    
    def get_all_bots(self):
        """Get all bot names"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM bots ORDER BY created_at')
            return [row['name'] for row in cursor.fetchall()]
    
    def bot_exists(self, bot_name):
        """Check if bot exists"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM bots WHERE name = ?', (bot_name,))
            return cursor.fetchone() is not None
    
    # ====================== Backup Methods ======================
    def add_backup(self, bot_name, serial, created_at, password, parent_serial='-'):
        """Add a new backup"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO backups (serial, bot_name, created_at, password, parent_serial)
                VALUES (?, ?, ?, ?, ?)
            ''', (serial, bot_name, created_at, password, parent_serial))
            conn.commit()
            return cursor.rowcount > 0
    
    def delete_backup(self, serial):
        """Delete a backup by serial"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM backups WHERE serial = ?', (serial,))
            conn.commit()
            return cursor.rowcount > 0
    
    def get_backups_for_bot(self, bot_name):
        """Get all backups for a bot"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT serial, parent_serial, created_at, password
                FROM backups 
                WHERE bot_name = ?
                ORDER BY created_at
            ''', (bot_name,))
            return [
                {
                    'serial': row['serial'],
                    'parent_serial': row['parent_serial'],
                    'created_at': row['created_at'],
                    'password': row['password']
                }
                for row in cursor.fetchall()
            ]
    
    def get_backup(self, serial):
        """Get backup details by serial"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT serial, bot_name, parent_serial, created_at, password
                FROM backups WHERE serial = ?
            ''', (serial,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # ====================== Branch Methods ======================
    def add_branch(self, backup_serial, epoch, password_hash):
        """Add a branch to a backup"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO branches (backup_serial, epoch, password_hash)
                VALUES (?, ?, ?)
            ''', (backup_serial, epoch, password_hash))
            conn.commit()
            return cursor.rowcount > 0
    
    def remove_branch(self, backup_serial, epoch, password_hash):
        """Remove a branch from a backup"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM branches 
                WHERE backup_serial = ? AND epoch = ? AND password_hash = ?
            ''', (backup_serial, epoch, password_hash))
            conn.commit()
            return cursor.rowcount > 0
    
    def get_branches(self, backup_serial):
        """Get all branches for a backup"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT epoch, password_hash
                FROM branches 
                WHERE backup_serial = ?
            ''', (backup_serial,))
            return [(row['epoch'], row['password_hash']) for row in cursor.fetchall()]
    
    def branch_exists(self, backup_serial, epoch, password_hash):
        """Check if a branch exists"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 1 FROM branches 
                WHERE backup_serial = ? AND epoch = ? AND password_hash = ?
            ''', (backup_serial, epoch, password_hash))
            return cursor.fetchone() is not None
