from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from .config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    import hashlib
    import secrets
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}:{key.hex()}"

def verify_password(stored_password_hash: str, provided_password: str) -> bool:
    import hashlib
    import secrets
    try:
        salt, key_hex = stored_password_hash.split(":", 1)
        key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False

def init_db():
    from . import models  # Ensure models are registered with Base.metadata
    from sqlalchemy import text
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        for stmt in [
            "ALTER TABLE scan_history ADD COLUMN sender VARCHAR;",
            "ALTER TABLE scan_history ADD COLUMN channel VARCHAR DEFAULT 'sms';",
            "ALTER TABLE scan_history ADD COLUMN is_red_flagged BOOLEAN DEFAULT 0;"
        ]:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass

    # Seed default demo account if not exists
    try:
        with SessionLocal() as session:
            admin = session.query(models.User).filter(models.User.email == "admin@threatguard.ai").first()
            if not admin:
                demo_user = models.User(
                    full_name="Monish Yadav (Lead SOC)",
                    email="admin@threatguard.ai",
                    password_hash=hash_password("password123"),
                    role="Lead Security Officer"
                )
                session.add(demo_user)
                session.commit()
    except Exception as e:
        print("Note on user seeding:", e)
