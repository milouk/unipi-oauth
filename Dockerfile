# Stage 0: Common ENV variables for all build stages
FROM python:3.7-buster

RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y dumb-init

ENV PYTHONUNBUFFERED 1

RUN mkdir /app

WORKDIR /app

COPY . /app/

RUN pip install -r requirements.txt

RUN ["chmod", "+x", "/app/contrib/entrypoint_dev.sh"]

CMD ["/app/contrib/entrypoint_dev.sh"]

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
