from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import contextlib
import sqlite3

# CONFIG params
KEY = b"super_secret_key"
IV = b'0' * 16

class SVManager:
    """
    This class provides an interface for managing SecureVaults stored in a database.
    Our database is formed by a single table called `devices`, where each secure vault has associated an IoT device
    since each one has a unique identifier.
    """
    def __init__(self, db_name: str) -> None:
        """
        :param db_name: database name (the file name should be end without db)
        """
        if db_name is not None:
            self._db_name: str = db_name

        # database creation if the table exist
        with self._connect() as (conn, cur):
            cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_ID VARCHAR(30) PRIMARY KEY,
                secure_vault TEXT DEFAULT NULL
            )
            """)
            conn.commit()

    @contextlib.contextmanager
    def _connect(self) -> (sqlite3.Connection, sqlite3.Cursor):
        """
        Create a connection with the database based on a context manager

        :return: connection and cursor objects
        """
        conn: sqlite3.Connection = sqlite3.connect(self._db_name)
        cur: sqlite3.Cursor = conn.cursor()

        yield conn, cur

        cur.close()
        conn.close()

    def get_SV(self, id: str) -> str:
        """
        Get the secure vault associated with the given ID.

        :param id: identifier for IoT device associated to a secure vault

        :return: secure vault
        """
        with self._connect() as (_, cur):
            cipher = AES.new(KEY, AES.MODE_CBC, IV)

            vault = cur.execute(f"SELECT secure_vault FROM devices WHERE device_ID=?", (id,)).fetchone()[0]

            return cipher.decrypt(bytes.fromhex(vault)).decode()

    def insert_device(self, id: str) -> None:
        """
        Insert unregistered device into the database.

        :param id: identifier for IoT device associated to a secure vault
        """
        if not self._check_id_existence(id):
            with self._connect() as (conn, cur):
                cur.execute("INSERT INTO devices (device_ID) VALUES (?)", (id,))
                conn.commit()
        else:
            print(f"Device with ID {id} already registered!")

    def update_SV(self, device: str, sv: str) -> None:
        """
        Update an existing secure vault associated with the given ID.

        :param device: identifier for IoT device associated to a secure vault
        :param sv: new value for secure vault
        """
        if self._check_id_existence(device):
            with self._connect() as (conn, cur):
                cipher = AES.new(KEY, AES.MODE_CBC, IV)

                cur.execute("UPDATE devices SET secure_vault=? WHERE device_ID=?", (cipher.encrypt(pad(sv.encode(), AES.block_size,)).hex(), device))
                conn.commit()
        else:
            print(f"Device with ID {device} not found!")

    def _check_id_existence(self, id: str) -> bool:
        """
        Check if the given ID is already registered into the database, or not.

        :param id: identifier for IoT device which we want to check its existence

        :return: True if it exists, False otherwise
        """
        with self._connect() as (_, cur):
            return cur.execute("SELECT * FROM devices WHERE device_ID=?", (id,)).fetchone() is not None