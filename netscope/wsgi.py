from app import create_app

app = create_app()

# Worker entry point: `celery -A wsgi:celery_app worker --loglevel=info`
celery_app = app.extensions["celery"]
