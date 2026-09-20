"""AWS Lambda entry point for the AI Doctor FastAPI application."""

from mangum import Mangum

from backend.main import app

handler = Mangum(app, lifespan="off")
