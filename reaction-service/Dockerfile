FROM python:3.11-slim

WORKDIR /app

COPY reaction_common/ ./reaction_common/
COPY reaction-service/ .

CMD ["python", "-u", "main.py"]
