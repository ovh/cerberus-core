# cerberus-core #

## Summary ##

This tool aims to help ISP manage abuse on their network by providing
a set of tools such as an email parser and classification, a ticketing
system, an API and an UX for operators (with cerberus-ux project).

This tool can be easily expanded by implementing new `python-rq`jobs.


## Try it ##

### The easy way (Docker) ###

To test the poc (not persistent), run (tested with version 1.9.1):

    $ docker build -t cerberus .

Then, you just need to run it with your abuse email inbox settings (over IMAPS):

    $ docker run -e EMAIL_HOST=mx.domain.com -e EMAIL_PORT=993 -e EMAIL_LOGIN=login@domain.com -e EMAIL_PASS=pass -p 6060:6060 -t cerberus

and browse `http://127.0.0.1:6060` with default login admin:admin , and voila

![cerberus](https://i.imgur.com/psafNaK.gif)

If something goes wrong, enter the docker and check the logs in `/home/cerberus/cerberus-core/*.log`

### The manual way ###

This project is mainly based on **Django**, **Flask**, **RQ** and **Rq-Scheduler**. To setup cerberus-core, you'll need:

 * A Linux environment
 * Python 2.7+
 * Packages `python-dev` and `python-pip`
 * A PostgreSQL database (9.4.x or greater)
 * An HTTP Server for cerberus-ux (not included in this project)
 * A Redis server
 * A MX supporting IMAPS
 * A scheduler (cron, supervisor, ...)

When all of these requirements are met, you can install the tool:

 1. Download the zipfile or checkout the sources.
 2. install python dependencies (`apt-get install python-dev python-pip`)
 3. Run `pip install -r requirements/common.txt` in order to setup dependencies

You should **take a look at docker directory** for further informations.

## Running ##

Start the scheduler:

    $ rqscheduler &

You can now insert theses entries in your favorite scheduler:

 * Schedule `rqcheduler`, `event/email_fetcher.py`, `worker/worker.py` and `uwsgi --http-socket 8080 api/uwsgi.ini` to be run as a daemon.
 * Schedule `event/workflow.py` to be run every minute.
 * Schedule `event/stats.py` to be run every quarter hour.

The whole project use `python-rq` and `rq-scheduler`. You can see jobs status with:

    $ rq-info

## Concept ##

### Plaintiff ###

(Law) A a person who brings a civil action in a court (aka claimant).

### Defendant ###

(Law) A person or entity against whom an action or claim is brought in a court of law.
It is one of your customer who is suspected of illegal activities on his service(s).

### Service ###

A Defendant has suscribed to one or more services(s) (product(s)) your company offers. It can be ADSL, hosting, email services ...

### Provider ###

The source of the email. It can be directly the plaintiff or an representative third party.

### Report ###

One Provider + one Category. If a defendant is identified, the report is linked to a defendant, a service and contains item(s).

### Ticket ###

One or more reports + one Category. It cans bel linked to a defendant/service, so all reports themselves linked to this defendant/service.

### Item ###
        
Fraudulent URL/IP/FQDN found in an email.

### Action ###

An action on a customer's service (suspend, shutdown, breach of contract).

## Workflow ##

An email can generates one or more reports (if multiple defendants are identified). Just one if no defendant is identified.
These reports can be attached to existing ticket or create one if the provider is "trusted".
So tickets can have multiple reports/providers.

So **not all reports are attached to tickets**. It's important, operators **process tickets, not reports**. Reports add weight to tickets.

All the effective jobs are done with ticket: customer interaction (emails), action on service ...

There's an specific/automatic workflow for **phishing** ticket/report described in `doc/source/phishing.png`.
A "Phishing-trusted reporter" is a provider with an `apiKey` (see `abuse/models.py`).

You can see full cerberus models's relationship in `doc/source/models.png`.

## Configuration ##

### Project structure ###

 * `abuse`: Django app models description.
 * `adapters`: Abstract classes providing way to implement core functions.
 * `api`: cerberus-core API for cerberus-ux.
 * `default`: default implementation of adapters abtract classes.
 * `doc`: documentation.
 * `docker`: files needed to build docker.
 * `event`: event-based jobs to be consume by python-rq workers.
 * `factory`: the factory for adapters implementations.
 * `requirements`: pip requirements.
 * `tests`: unit tests.
 * `utils`: utils functions for worker and API.
 * `worker`: python-rq workers.

### General settings ###

For security purpose, most of setting values must be defined as VARENV. So, to configure the tool, you just have to export following environment variables:

 * EMAIL_STORAGE_DIR: The folder where to store fetched and sent emails
 * MAGIC_SMTP_HEADER: King of tag in SMTP header defining e-mail source (see next section)
 * API_HOST: The IP address of cerberus-core API
 * API_PORT: The TCP port of cerberus-core API
 * EMAIL_HOST: IP or domain of your MX
 * EMAIL_PORT: The TCP port of your MX (IMAPS)
 * EMAIL_LOGIN: Username used to poll incoming e-mails
 * EMAIL_PASS: Password for previous username
 * REDIS_HOST: The IP address of the Redis Server
 * REDIS_PORT: The TCP port of the Redis Server
 * SECRET_KEY: The Django secret key
 * PG_NAME: The name of the PostgreSQL db
 * PG_USER: The username to use for previous db
 * PG_PASS: The password of this user
 * PG_HOST: The IP address of PostgreSQL db
 * PG_PORT: The TCP port of PostgreSQL db

In `settings.py` you can see how this different varenv are used + other settings description. **Really, you should edit this file.**

### A "trusted" email ? ###

As you can see, a required varenv is called MAGIC_SMTP_HEADER.
Since everybody is able to send an email pretending being Microsoft, NSA or whatever,
it's important to check the identity of the mail send with a well-kept secret.
The easier way to do so is to assign a single e-mail address per organization you keep secret.

Using the MX features, the mail must be validated and tagged with the previous MAGIC_SMTP_HEADER.
We recommend to keep this header name secret too. No matter the value of this header, if it's present, the email is trusted.

### Network IPs ###

When you're done, with general config, the tool is almost ready to be run. You now have to tell the IPs your network is made of.
Everything you have to do is opening the file utils/ips.py and add your CIDRs (only one per line).

### Implementing your own core functions ###

You'll maybe see in the file `settings.py`, there is a way to provide your implementation(s).
By default, a very basic implementation is provided for each adapter. (see abstract documentation)

Required adapters implementations are:

 * adapters.services.storage.abstract.StorageServiceBase
 * adapters.dao.customer.abstract.CustomerDaoBase
 * adapters.services.phishing.abstract.PhishingServiceBase
 * adapters.services.mailer.abstract.MailerServiceBase
 * adapters.services.action.impl.ActionServiceBase

Optional, but usefull, are:

 * adapters.services.kpi.abstract.KPIServiceBase
 * adapters.services.search.abstract.SearchServiceBase
 * adapters.dao.reputation.impl.ReputationDaoBase

You can code your own service(s) by implementing `adapters.services.*.abstract.*` and your own DAO by implementing `adapters.dao.*.abstract.*.`
Then, tell cerberus-core to use this implementations by editing the property CUSTOM_IMPLEMENTATIONS.

You can find implementation and expected return value in `default.adapters`.

### Add features ###

You can easily add event in `event/` and there associated functions in `worker/`
You can add template for provider in `worker/parsing/templates`. If your template is well formatted, it will be added to parser regexp.

## API ##

Once everything is running, you can start using the API. By default, it's listening to the port 8080. Full endpoints description are available in documentation

**Be careful, this is not a RESTFul API.** The main goal of this API is to interface DB with `ovh/cerberus-ux` project.

## Documentation ##

You can build the full documentation with:

    $ sphinx-build -b html doc/source doc/build
