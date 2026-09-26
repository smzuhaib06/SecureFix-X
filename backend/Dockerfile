FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi==0.111.0 uvicorn[standard]==0.29.0 \
    pydantic==2.7.1 python-dotenv==1.0.1 aiofiles==23.2.1 httpx==0.27.0

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
