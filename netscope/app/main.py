from fastapi import FastAPI

from app.api.routes import health

app = FastAPI(
    title="NetScope API",
    description="Network Traffic Analysis and Intelligence Platform",
    version="0.1.0",
)

app.include_router(health.router)


@app.get("/")
def root():
    return {"message": "Welcome to NetScope"}
