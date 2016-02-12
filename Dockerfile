FROM debian:latest
MAINTAINER Simon Vasseur "simon.vasseur@corp.ovh.com"

RUN apt-get update
RUN apt-get install -y git apache2 python2.7 postgresql redis-server python-pip python-psycopg2 python-dev supervisor

RUN useradd -ms /bin/bash cerberus

USER postgres
RUN /etc/init.d/postgresql start \
    && psql --command "CREATE USER cerberus WITH SUPERUSER PASSWORD 'cerberus';" \
    && createdb -O cerberus abuse 

USER root
WORKDIR /home/cerberus

COPY docker/supervisor/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/supervisor/cerberus.conf \
    docker/supervisor/fetcher.conf \
    docker/supervisor/workflow.conf \
    docker/supervisor/worker.conf \
    docker/supervisor/stats.conf \
    /etc/supervisor/conf.d/

COPY abuse /abuse
COPY adapters /adapters
COPY api /api
COPY default /default
COPY event /event
COPY factory /factory
COPY manage.py /manage.py
COPY requirements /requirements
COPY requirements.txt /requirements.txt
COPY settings.py /settings.py
COPY utils /utils
COPY worker /worker

COPY docker/cerberus-ux.tar.gz /cerberus-ux.tar.gz

RUN mkdir cerberus-core \
    && cd cerberus-core \
    && mv /abuse . \
    && mv /adapters . \
    && mv /api . \
    && mv /default . \
    && mv /event . \
    && mv /factory . \
    && mv /manage.py . \
    && mv /requirements . \
    && mv /requirements.txt . \
    && mv /settings.py . \
    && mv /utils . \
    && mv /worker . \
    && cp abuse/fixtures/data.json abuse/fixtures/initial_data.json \
    && chown -R cerberus:cerberus /home/cerberus/cerberus-core \
    && pip install -r requirements/dev.txt \
    && ln -s /etc/supervisor/supervisord.conf /etc/supervisord.conf \
    && mkdir ../cerberus-ux \
    && cd ../cerberus-ux \
    && tar xvzf /cerberus-ux.tar.gz \
    && chown -R www-data:www-data /home/cerberus/cerberus-ux/client \
    && sed -i 's/80/6060/g' /etc/apache2/ports.conf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 6060

COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf
COPY docker/crontab /etc/cron.d/cerberus
RUN chmod 0644 /etc/cron.d/cerberus

COPY docker/run.sh /run.sh
COPY docker/cerberus.sh /home/cerberus/cerberus-core/
RUN chmod 0644 /home/cerberus/cerberus-core/cerberus.sh

CMD /run.sh
