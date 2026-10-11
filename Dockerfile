FROM python:3.12-slim

# nmap is required for real port/service scanning (the app falls back to a
# pure-python socket scanner if it's ever missing, but nmap gives far
# better results, including service/version fingerprinting).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        default-libmysqlclient-dev \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/reports

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "600", "app:app"]
