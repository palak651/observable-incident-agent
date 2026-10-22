
import os
import json
import sqlite3


class Store:
    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with self.connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    state_json TEXT NOT NULL
                )
            """)

    def connect(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def get_run(self, run_id):
        with self.connect() as con:
            row = con.execute(
                "SELECT * FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()

        if not row:
            return None

        return {
            "run_id": row["run_id"],
            "request_hash": row["request_hash"],
            "state": json.loads(row["state_json"]),
        }

    def put_run(self, run_id, request_hash, state):
        with self.connect() as con:
            con.execute(
                "INSERT INTO runs VALUES (?, ?, ?)",
                (
                    run_id,
                    request_hash,
                    json.dumps(state, separators=(",", ":")),
                ),
            )
            con.commit()

    def save_state(self, run_id, state):
        with self.connect() as con:
            con.execute(
                "UPDATE runs SET state_json = ? WHERE run_id = ?",
                (
                    json.dumps(state, separators=(",", ":")),
                    run_id,
                ),
            )
            con.commit()
