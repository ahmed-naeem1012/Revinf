from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Add your database URL here
DATABASE_URL = "mysql://root:MySQL@123@127.0.0.1:3306/my_project"

# Alembic Config
config = context.config
config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Interpret the config file for Python logging
fileConfig(config.config_file_name)

# Since we are using Peewee, leave target_metadata as None
target_metadata = None

def run_migrations_offline():
    """
    Run migrations in 'offline' mode.
    """
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """
    Run migrations in 'online' mode.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
