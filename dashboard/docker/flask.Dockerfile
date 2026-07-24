FROM python:3.12-slim

WORKDIR /app

COPY flask_app/ /app/flask_app/

ENV PATH="/venv/bin:$PATH"

EXPOSE 5000

CMD ["python", "-m", "flask_app.app"]
