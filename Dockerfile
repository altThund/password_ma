FROM python:3.7-buster

EXPOSE 80/tcp
EXPOSE 443/tcp

RUN /usr/local/bin/python -m pip install --upgrade pip

WORKDIR /project

COPY flask_app/ /project

RUN pip install flask flask_sqlalchemy pymysql flask-login pbkdf2 pycryptodome flask-wtf

RUN pip freeze > requirements.txt

RUN pip install -r requirements.txt

ENTRYPOINT ["python"]

CMD ["app.py"]

