FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY . .

EXPOSE 8000

# Serve with gunicorn (app:app is the Flask WSGI callable in app.py).
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "app:app"]
