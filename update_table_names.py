from peewee import MySQLDatabase
from app.config.database import ConfigDatabase

def migrate_database():
    db = ConfigDatabase.database

    try:
        db.connect()

        # Rename tables
        db.execute_sql("RENAME TABLE user TO users;")
        db.execute_sql("RENAME TABLE otp TO otps;")
        db.execute_sql("RENAME TABLE userserver TO user_servers;")
        db.execute_sql("RENAME TABLE server TO servers;")
        db.execute_sql("RENAME TABLE userdomains TO user_domains;")
        db.execute_sql("RENAME TABLE mailbox TO mailboxes;")

        # Add created_at column if it doesn't exist
        tables_to_update = [
            "users",
            "otps",
            "user_servers",
            "servers",
            "user_domains",
            "mailboxes",
        ]

        for table in tables_to_update:
            db.execute_sql(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS created_at DATETIME DEFAULT CURRENT_TIMESTAMP;"
            )

        print("Migration completed successfully!")
    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    migrate_database()
