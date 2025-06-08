# app/migrations/env.py
from alembic import context
from sqlalchemy import engine_from_config, pool
from ..core.database import db
from ..config.settings import Config

config = context.config
config.set_main_option('sqlalchemy.url', Config.SQLALCHEMY_DATABASE_URI)
connectable = engine_from_config(
    config.get_section(config.config_ini_section),
    prefix='sqlalchemy.',
    poolclass=pool.NullPool)

with connectable.connect() as connection:
    context.configure(
        connection=connection,
        target_metadata=db.metadata
    )

    with context.begin_transaction():
        context.run_migrations()