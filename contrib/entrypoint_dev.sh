#!/bin/bash

cd /app

python manage.py makemigrations oauth2
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
