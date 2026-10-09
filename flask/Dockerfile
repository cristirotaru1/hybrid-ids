FROM python:3.12-slim

WORKDIR /app

COPY flask/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY reaction_common/ ./reaction_common/
COPY flask/src/ .

EXPOSE 5000

CMD ["python", "app.py"]
