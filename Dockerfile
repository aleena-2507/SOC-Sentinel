FROM python:3.10-slim

WORKDIR /app

COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .

EXPOSE 5000

CMD ["python", "-m", "app.app"]