FROM python:3.12-bookworm

WORKDIR /workspace

COPY . .

RUN pip install --no-cache-dir --upgrade -r requirements.txt


EXPOSE 8080

CMD ["python3", "app.py"]
