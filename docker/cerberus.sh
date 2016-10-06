#!/bin/bash

rqscheduler &
uwsgi --http-socket 0.0.0.0:8080 api/uwsgi.ini &
