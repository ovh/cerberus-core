#!/bin/bash

rqscheduler &
python manage.py migrate auth
python manage.py migrate
uwsgi --http-socket 0.0.0.0:8080 api/uwsgi.ini
