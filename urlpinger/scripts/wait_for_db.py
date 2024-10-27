import os
import time

import psycopg2

DBUSER = os.getenv("PG_DB_USER=", "urlpinger")
DBPASSWORD = os.getenv("PG_DB_PASSWORD", "urlpinger")
DBHOST = os.getenv("PG_DB_HOST", "localhost")
DBNAME = os.getenv("PG_DB_NAME", "urlpinger")


while True:
    try:
        psycopg2.connect(
            dbname=DBNAME,
            user=DBUSER,
            password=DBPASSWORD,
            host=DBHOST,
            port="5432",
        )
        break
    except psycopg2.OperationalError:
        print("Waiting for postgres...")
        time.sleep(1)
