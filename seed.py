import json
from pkpl_group.db import Group, conn, setup_database
import csv

setup_database()

with open("shuffled.json") as f:
    generated = json.load(f)

for i, target in enumerate(generated):
    Group(
        id=i + 1,
        links=[],
        credentials=[],
        additional="",
        pentester_group=target,
    ).create()

with open("anggota.csv", mode="r") as file:
    csv_reader = csv.DictReader(file)
    cursor = conn.cursor()
    for row in csv_reader:
        members = [
            row["Ketua"].split("-")[0].strip(),
            row["Anggota 2"].split("-")[0].strip(),
            row["Anggota 3"].split("-")[0].strip(),
            row["Anggota 4"].split("-")[0].strip(),
            row["Anggota 5"].split("-")[0].strip(),
        ]

        for mem in members:
            if not mem:
                continue

            groupno = int(row["No"])
            cursor.execute(
                """
                INSERT INTO group_users (npm, group_id)
                VALUES (?, ?)
                """,
                (mem, groupno),
            )

    conn.commit()
