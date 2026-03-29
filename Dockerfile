FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY la_cna_accio_bridge.py .

EXPOSE 5000

ENV PORT=5000

CMD ["python3", "la_cna_accio_bridge.py"]
