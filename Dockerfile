FROM python:3.13-slim

COPY ./requirements.txt /code/requirements.txt

RUN pip install -r /code/requirements.txt

COPY ./app /code/app

CMD ["python", "/code/app/main.py"]