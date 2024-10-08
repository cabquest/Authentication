FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install boto3

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 9639

CMD ["python", "app.py"]