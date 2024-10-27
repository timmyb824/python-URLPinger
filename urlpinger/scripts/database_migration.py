import os

import psycopg2
import structlog
from psycopg2.extras import Json

logger = structlog.get_logger(__name__)


def connect_to_database(host, port, dbname, user, password):
    try:
        logger.info("Connecting to the database", extra={"host": host})
        return psycopg2.connect(
            host=host, port=port, dbname=dbname, user=user, password=password
        )
    except psycopg2.Error as e:
        logger.error("Error connecting to the database: %s", e)
        raise


def adapt_complex_json(val):
    return Json(val) if isinstance(val, (dict, list)) else val


def copy_data(source_conn, destination_conn, tables):
    try:
        with source_conn.cursor() as source_cursor:
            with destination_conn.cursor() as destination_cursor:
                # Disable triggers temporarily
                destination_cursor.execute("SET session_replication_role = 'replica';")

                # Truncate all tables with CASCADE
                logger.info("Truncating all tables")
                destination_cursor.execute(
                    f"TRUNCATE TABLE {', '.join(tables)} CASCADE;"
                )

                for table in tables:
                    logger.info("Copying data from table", extra={"table": table})

                    source_cursor.execute(f"SELECT * FROM {table}")
                    if data := source_cursor.fetchall():
                        columns = [desc[0] for desc in source_cursor.description]
                        placeholders = ", ".join(["%s"] * len(columns))
                        insert_stmt = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"

                        # Adapt complex JSON values
                        adapted_data = []
                        for i, row in enumerate(data):
                            try:
                                adapted_row = tuple(
                                    adapt_complex_json(val) for val in row
                                )
                                adapted_data.append(adapted_row)
                            except Exception as e:
                                logger.error(
                                    "Error adapting row in table",
                                    extra={"table": table, "row": i, "error": e},
                                )
                                logger.error("Problematic row", extra={"row": row})
                                raise

                        destination_cursor.executemany(insert_stmt, adapted_data)

                    destination_conn.commit()
                    logger.info("Data copied from table", extra={"table": table})

                # Re-enable triggers
                destination_cursor.execute("SET session_replication_role = 'origin';")
    except psycopg2.Error as e:
        logger.error("Error copying data", extra={"error": e})
        raise
    finally:
        source_conn.close()
        destination_conn.close()


def main():
    source_host = os.getenv("PG_DB_HOST")
    source_port = os.getenv("PG_DB_PORT")
    source_dbname = os.getenv("PG_DB_DATABASE")
    source_user = os.getenv("PG_DB_USER")
    source_password = os.getenv("PG_DB_PASSWORD")

    destination_host = os.getenv("PG_DB_HOST_QA")
    destination_port = os.getenv("PG_DB_PORT")
    destination_dbname = os.getenv("PG_DB_DATABASE")
    destination_user = os.getenv("PG_DB_USER")
    destination_password = os.getenv("PG_DB_PASSWORD_QA")

    tables = [
        "endpoint_config",
        "endpoint_uptime_history",
    ]

    try:
        source_conn = connect_to_database(
            source_host, source_port, source_dbname, source_user, source_password
        )
        destination_conn = connect_to_database(
            destination_host,
            destination_port,
            destination_dbname,
            destination_user,
            destination_password,
        )

        copy_data(source_conn, destination_conn, tables)

    except Exception as e:
        logger.error("An error occurred while copying data", extra={"error": e})


if __name__ == "__main__":
    main()
