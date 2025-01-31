import contextlib
import sqlite3

class SVManager:
    """
    This class provides an interface for managing SecureVaults stored in a database.
    Our database is formed by a single table called `SecureVaults`, where each secure vault has associated an IoT device
    since each one has a unique identifier.
    """
    def __init__(self, db_name: str):
        """
        Initialize new instance of the class.

        :param db_name: database name
        """
        if db_name is not None:
            self._db_name : str = db_name if db_name.endswith(".db") else db_name + ".db"

    @contextlib.contextmanager
    def connect(self) -> (sqlite3.Connection, sqlite3.Cursor):
        """
        Create a connection with the database based on a context manager

        :return: connection and cursor objects
        """
        conn: sqlite3.Connection = sqlite3.connect(self._db_name)
        cur: sqlite3.Cursor = conn.cursor()

        yield conn, cur

        cur.close()
        conn.close()

    def get_SV(self, cur: sqlite3.Cursor, id: str) -> tuple:
        """
        Get the secure vault associated with the given ID.

        :param cur: database cursor
        :param id: identifier for IoT device associated to a secure vault

        :return: secure vault
        """
        return cur.execute(f"SELECT secure_vault FROM SecureVaults WHERE id=?", (id,)).fetchone()

    def insert_SV(self, conn: sqlite3.Connection, cur: sqlite3.Cursor, id: str, sv: str) -> None:
        """
        Insert new secure vault associated with the given ID.

        :param conn: database connection
        :param cur: database cursor
        :param id: identifier for IoT device associated to a secure vault
        :param sv: secure vault that we want to insert into the database
        """
        if self._check_id_existence(id):
            # TODO: check secure vault structure
            cur.execute("INSERT INTO SecureVaults (sv) VALUES (?)", (sv,))
            conn.commit()
        else:
            print("ID not found!")

    def update_SV(self, conn: sqlite3.Connection, cur: sqlite3.Cursor, id: str, sv: str) -> None:
        """
        Update an existing secure vault associated with the given ID.

        :param conn: database connection
        :param cur: database cursor
        :param id: identifier for IoT device associated to a secure vault
        :param sv: new value for secure vault
        """
        if self._check_id_existence(id):
            # TODO: check secure vault structure
            cur.execute("UPDATE SecureVaults SET sv=? WHERE id=?", (sv, id))
            conn.commit()
        else:
            print("ID not found!")

    def _check_id_existence(self, cur: sqlite3.Cursor, id: str) -> bool:
        """
        Check if the given ID is already registered into the database, or not.

        :param cur: database cursor
        :param id: identifier for IoT device which we want to check its existence

        :return: True if it exists, False otherwise
        """
        return cur.execute("SELECT * FROM SecureVaults WHERE id=?", (id,)).fetchone() is not None