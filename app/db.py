import json
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from . import config


class Base(DeclarativeBase):
    pass


def make_engine():
    database_url = config.DB_URL
    is_sqlite = database_url.startswith("sqlite")
    sqlite_connect_arguments = {"check_same_thread": False, "timeout": 15}
    database_engine = create_engine(database_url, connect_args=sqlite_connect_arguments if is_sqlite else {},
                                    json_serializer=lambda value: json.dumps(value, default=str))

    if is_sqlite:
        @event.listens_for(database_engine, "connect")
        def _configure_connection(dbapi_connection, _connection_record):
            dbapi_connection.isolation_level = None
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=15000")
            cursor.close()

        @event.listens_for(database_engine, "begin")
        def _begin_immediate(connection):
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    return database_engine


engine = make_engine()
SessionFactory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=True)


@contextmanager
def session_scope():
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


AUDIT_TRIGGERS = [
    """CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
]


def init_db():
    from . import models
    Base.metadata.create_all(engine)
    if str(engine.url).startswith("sqlite"):
        with engine.begin() as connection:
            for trigger_sql in AUDIT_TRIGGERS:
                connection.exec_driver_sql(trigger_sql)
