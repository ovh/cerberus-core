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
/usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
