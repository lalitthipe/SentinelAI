from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# This URL tells SQLAlchemy: which database engine (postgresql),
# username, password, host, port, and database name.
# These match what you set in docker-compose.yml earlier.
DATABASE_URL = "postgresql://sentinel:sentinel_dev_pw@localhost:5432/sentinelai"

# The "engine" is the actual connection pool to Postgres.
engine = create_engine(DATABASE_URL)

# A "session" is a temporary workspace for talking to the DB —
# you open one, do some queries/inserts, then close it.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the parent class all our table models will inherit from.
Base = declarative_base()

# FastAPI will call this function per-request to get a DB session,
# and guarantees it closes afterward even if an error happens.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
