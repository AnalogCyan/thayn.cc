#! WIP Docker reimplementation of the app

FROM python:3.11

WORKDIR /app

ADD . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8080"]
