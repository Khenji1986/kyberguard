FROM python:3.11-slim

WORKDIR /app

# Dependencies installieren
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Non-root user anlegen
RUN groupadd -r botuser && useradd -r -g botuser -u 1001 botuser

# App kopieren
COPY . .

# Verzeichnisse für non-root zugänglich machen
RUN mkdir -p /app/data && chown -R botuser:botuser /app

USER botuser

# Bot starten
CMD ["python", "bot.py"]
