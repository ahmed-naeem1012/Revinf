from app.users.model import User  # Import your User model
from app.config.database import ConfigDatabase

if __name__ == "__main__":
    # Instantiate ConfigDatabase and pass the list of models
    db_config = ConfigDatabase(models=[User])
    
    # Connect to the database and refresh tables
    try:
        print("Connecting to the database...")
        ConfigDatabase.database.connect()
        db_config.refresh_tables()
        print("Tables created successfully!")
    except Exception as e:
        print("Error while creating tables:", e)
    finally:
        ConfigDatabase.database.close()