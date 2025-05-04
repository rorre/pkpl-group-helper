from dataclasses import dataclass
import json
import os
import sqlite3

conn: sqlite3.Connection = sqlite3.connect(os.getenv("DB_PATH", "pkpl.db"), check_same_thread=False)


@dataclass
class Credential:
    username: str
    password: str
    notes: str

    def to_dict(self):
        return {
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
        }


@dataclass
class Group:
    id: int
    links: list[str]
    credentials: list[Credential]
    additional: str
    pentester_group: int

    @staticmethod
    def from_table_row(row):
        return Group(
            id=row[0],
            links=json.loads(row[1]),
            credentials=[Credential(**cred) for cred in json.loads(row[2])],
            additional=row[3],
            pentester_group=row[4],
        )

    def save(self):
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE groups
            SET links = ?, credentials = ?, additional = ?
            WHERE id = ?
        """,
            (
                json.dumps(self.links),
                json.dumps([cred.to_dict() for cred in self.credentials]),
                self.additional,
                self.id,
            ),
        )
        conn.commit()
        return self

    def create(self):
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO groups (links, credentials, additional, pentester_group)
            VALUES (?, ?, ?, ?)
        """,
            (
                json.dumps(self.links),
                json.dumps([cred.to_dict() for cred in self.credentials]),
                self.additional,
                self.pentester_group,
            ),
        )
        conn.commit()
        self.id = cursor.lastrowid
        return self


def setup_database():
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            links TEXT,
            credentials TEXT,
            additional TEXT,
            pentester_group INTEGER,
            FOREIGN KEY (pentester_group) REFERENCES groups (id)
        )
    """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS group_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            npm TEXT,
            group_id INTEGER,
            FOREIGN KEY (group_id) REFERENCES groups (id)
        )
    """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_group_users_npm ON group_users (npm)
    """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            npm TEXT,
            group_id INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            message TEXT,
            FOREIGN KEY (group_id) REFERENCES groups (id)
        )
        """
    )
    conn.commit()


def write_log(npm: str, group_id: int, message: str):
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO logs (npm, group_id, message)
        VALUES (?, ?, ?)
    """,
        (npm, group_id, message),
    )
    conn.commit()
    return cursor.lastrowid


def fetch_group(group_id: int) -> Group | None:
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM groups WHERE id = ?
    """,
        (group_id,),
    )
    row = cursor.fetchone()
    if row:
        return Group.from_table_row(row)
    return None


def fetch_group_by_npm(npm: str) -> Group | None:
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT g.* FROM groups g
        JOIN group_users gu ON g.id = gu.group_id
        WHERE gu.npm = ?
    """,
        (npm,),
    )
    row = cursor.fetchone()
    if row:
        return Group.from_table_row(row)
    return None


def fetch_group_to_pentest(pentester_group: int) -> Group | None:
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM groups WHERE pentester_group = ?
    """,
        (pentester_group,),
    )
    row = cursor.fetchone()
    if row:
        return Group.from_table_row(row)
    return None
