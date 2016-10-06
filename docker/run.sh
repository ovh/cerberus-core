#!/bin/bash

/etc/init.d/redis-server start
/etc/init.d/postgresql start
a2enmod rewrite
a2enmod proxy
a2enmod proxy_http
/etc/init.d/apache2 start
crontab /crontab
touch /var/log/cron.log
/etc/init.d/cron restart
cd /home/cerberus/cerberus-core
sleep 10
/usr/bin/python manage.py migrate auth
/usr/bin/python manage.py migrate
/usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
