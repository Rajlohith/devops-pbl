from fastapi import FastAPI

from app.api.routes import health

from .api.routes import packets

app = FastAPI(
    title="NetScope API",
    description="Network Traffic Analysis and Intelligence Platform",
    version="0.1.0",
)


@app.get("/")
def root():
    return {"message": "Welcome to NetScope"}


app.include_router(health.router)

app.include_router(packets.router)
