from fastapi import Depends
from sqlmodel import SQLModel, create_engine, Session
from .config import settings
from typing import Annotated

DATABASE_URL = f"postgresql://{settings.DATABASE_USERNAME}:{settings.DATABASE_PASSWORD}@{settings.DATABASE_HOST}:{settings.DATABASE_PORT}/{settings.DATABASE_NAME}"

engine = create_engine(DATABASE_URL, echo=True)
 
def get_session():
    with Session(engine) as session:
        yield session

SESSION_LOCAL = Annotated[Session, Depends(get_session)]