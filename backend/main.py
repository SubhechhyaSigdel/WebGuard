from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import scan

app = FastAPI(
    title="WebGuard API",
    description="A beginner-friendly web vulnerability scanner",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/api")

@app.get("/")
def root():
    return {"message": "WebGuard API is running!"}
