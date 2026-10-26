FROM python:3.11-slim

WORKDIR /app

COPY . /app

EXPOSE 8000
ENV PORT=8000
ENV HOST=0.0.0.0

CMD ["python", "run.py"]
