import argparse
import json
import os
from pathlib import Path

import psycopg
from psycopg import sql
import pymysql


parser = argparse.ArgumentParser()
parser.add_argument("database", choices=("postgresql", "mysql"))
arguments = parser.parse_args()
credentials = json.loads(
    (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "database.json").read_text()
)

if arguments.database == "postgresql":
    with psycopg.connect(
        host="/run/postgresql", dbname="postgres", user="postgres", autocommit=True
    ) as connection:
        connection.execute(
            sql.SQL("ALTER ROLE minecraft WITH LOGIN PASSWORD {}").format(
                sql.Literal(credentials["postgresql"])
            )
        )
        connection.execute("ALTER DATABASE luckperms OWNER TO minecraft")
else:
    with pymysql.connect(
        unix_socket="/run/mysqld/mysqld.sock", user="root", autocommit=True
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER USER 'mc_user'@'localhost' IDENTIFIED BY %s",
                (credentials["mysql"],),
            )
