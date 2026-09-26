FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0 \
    PyJWT==2.8.0 bcrypt==4.1.3 python-multipart==0.0.9

COPY . .

EXPOSE 8001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
