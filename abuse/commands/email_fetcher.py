#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016, OVH SAS
#
# This file is part of Cerberus-core.
#
# Cerberus-core is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
    Email fetcher for Cerberus
"""
import hashlib

from imaplib import IMAP4_SSL
from Queue import Queue
from threading import Thread
from time import sleep

import click

from flask.cli import with_appcontext

from ..services import StorageService
from ..services.storage import StorageServiceException
from ..tasks import enqueue


CHARSETS = (
    "iso-8859-1",
    "iso-8859-15",
    "utf-8",
    "ascii",
    "utf-16",
    "windows-1252",
    "cp850",
    "iso-8859-11",
)


def push_email(uid, messages):
    """
        Push to Storage Service
        Add a worker task
    """
    email = messages.get(uid)
    filename = hashlib.sha256(email).hexdigest()
    click.echo("[email-fetcher] new mail - UID %s - HASH %s" % (uid, filename))

    for chset in CHARSETS:
        try:
            email = email.decode(chset).encode("utf-8")
            break
        except UnicodeError:
            click.echo(
                "[email-fetcher] error while decoding email with charset %s" % chset
            )

    _push_to_storage_service(filename, email)
    _push_task_to_worker(filename, email)
    messages.pop(uid, None)


def _push_to_storage_service(filename, email):
    """ Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    try:
        StorageService.read(filename)
        click.echo("[email-fetcher] email %s already in Storage Service" % filename)
        return
    except StorageServiceException:
        pass

    StorageService.write(filename, email)
    click.echo("[email-fetcher] email %s pushed to Storage Service" % filename)


def _push_task_to_worker(filename, email):
    """ Push parsing task to worker

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    enqueue(
        "report.create_from_email",
        queue="email",
        email_content=email,
        filename=filename,
    )
    click.echo("[email-fetcher] task for email %s successfully created" % filename)


class Worker(Thread):
    """
        Thread executing tasks from a given tasks queue
    """

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as ex:
                click.echo("[email-fetcher] error in email worker: %s" % str(ex))
            finally:
                self.tasks.task_done()


class ThreadPool(object):
    """
        Pool of threads consuming tasks from a queue
    """

    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, args, **kargs):
        """
            Add a task to the queue
        """
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        """
            Add a list of tasks to the queue
        """
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        """
            Wait for completion of all the tasks in the queue
        """
        self.tasks.join()


class EmailFetcher(object):
    """ Main daemon, waiting for incoming email
    """

    def __init__(self, host, port, user, password):

        from flask import current_app

        self._logger = current_app.logger
        self._imap_conn = self._get_imap_connection(host, port, user, password)

    def fetch(self):
        """
            Infinite loop fetching email , lauching < 10 threads pushing email
            to storage service and worker
        """
        click.echo("[email-fetcher] fetching started.")
        pool = ThreadPool(5)

        while True:

            messages = self._get_messages()
            if not messages:
                sleep(1)
                continue

            uids = messages.keys()
            args = [(uid, messages) for uid in uids]
            pool.map(push_email, args)
            pool.wait_completion()

            for uid in uids:
                if uid not in messages:
                    self._imap_conn.uid("store", uid, "+FLAGS", r"(\Deleted)")

            self._imap_conn.expunge()
            sleep(1)

    def _get_imap_connection(self, host=None, port=None, user=None, passwd=None):
        """
            Connect to mailbox using IMAP
        """
        click.echo("[email-fetcher] connecting to %s inbox ..." % user)
        conn = IMAP4_SSL(host, port)
        conn.login(user, passwd)
        conn.select("INBOX")
        click.echo("[email-fetcher] connected.")
        return conn

    def _get_messages(self):
        """ Get all new emails
        """
        response = {}
        _, data = self._imap_conn.uid("search", None, "ALL")
        messages = data[0].split()

        click.echo("[email-fetcher] still %d emails to fetch" % len(messages))

        for message_uid in messages[:50]:
            _, data = self._imap_conn.uid("fetch", message_uid, "(RFC822)")
            body = data[0][1]
            response[message_uid] = body

        return response


@click.command("fetch-email", short_help="Runs Cerberus email fetcher.")
@with_appcontext
def fetch_email():
    """
        Main loop
    """
    from flask import current_app

    fetcher = EmailFetcher(**current_app.config["EMAIL_FETCHER"])
    fetcher.fetch()
