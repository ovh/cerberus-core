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
    Mail fetcher for Cerberus

    Elegant solution here: https://www.metachris.com/2016/04/python-threadpool/

"""

import hashlib
import inspect
import os
import socket
import ssl
import sys
from imaplib import IMAP4, IMAP4_SSL
from Queue import Queue
from threading import Thread
from time import sleep

CURRENTDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PARENTDIR = os.path.dirname(CURRENTDIR)
sys.path.insert(0, PARENTDIR)

# Init settings

import django
from django.conf import ImproperlyConfigured

try:
    django.setup()
    from django.conf import settings
except ImproperlyConfigured:
    from django.conf import global_settings, settings
    from config import settings as custom_settings

    for attr in dir(custom_settings):
        if not callable(getattr(custom_settings, attr)) and not attr.startswith("__"):
            setattr(global_settings, attr, getattr(custom_settings, attr))

    settings.configure()
    django.setup()

from adapters.services.storage.abstract import StorageServiceException
from factory.implementation import ImplementationFactory as implementations
from utils import utils
from utils.logger import get_logger


Logger = get_logger(os.path.basename(__file__))

CHARSETS = ('iso-8859-1', 'iso-8859-15', 'utf-8', 'ascii', 'utf-16', 'windows-1252', 'cp850', 'iso-8859-11')
HOST = settings.EMAIL_FETCHER['host']
PORT = settings.EMAIL_FETCHER['port']
USER = settings.EMAIL_FETCHER['login']
PASS = settings.EMAIL_FETCHER['pass']
STORAGE_DIR = settings.GENERAL_CONFIG['email_storage_dir']


def push_email(uid, messages):
    """
        Push to Storage Service
        Add a worker task
    """
    email = messages.get(uid)
    filename = hashlib.sha256(email).hexdigest()
    Logger.debug(unicode('New mail - UID %s - HASH %s' % (uid, filename)), extra={'hash': filename})

    for chset in CHARSETS:
        try:
            email = email.decode(chset).encode('utf-8')
            break
        except UnicodeError:
            Logger.debug(str('error while decoding email with charset %s' % (chset,)))

    _push_to_storage_service(filename, email)
    _push_task_to_worker(filename, email)
    messages.pop(uid, None)


def _push_to_storage_service(filename, email):
    """ Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    with implementations.instance.get_instance_of('StorageServiceBase', STORAGE_DIR) as cnx:
        try:
            cnx.read(filename)
            Logger.error(unicode('Email %s already in Storage Service' % (filename)))
            return
        except StorageServiceException:
            pass

        cnx.write(filename, email)
        Logger.info(unicode('Email %s pushed to Storage Service' % (filename)))


def _push_task_to_worker(filename, email):
    """ Push parsing task to worker

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    utils.email_queue.enqueue(
        'report.create_from_email',
        email_content=email,
        filename=filename,
    )
    Logger.info(unicode('Task for email %s successfully created' % (filename)))


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
                Logger.debug(unicode('error in email worker: %s' % str(ex)))
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
    def __init__(self):
        self._imap_conn = None

    def run(self):
        """
            Infinite loop fetching email , lauching < 10 threads pushing email
            to storage service and worker
        """
        try:
            self._imap_conn = get_imap_connection(host=HOST, port=PORT, user=USER, passwd=PASS)
        except (IMAP4.error, IMAP4.abort, IMAP4.readonly) as ex:
            Logger.error(unicode('Error in IMAP connection - %s' % (str(ex))))
            return
        except (socket.error, socket.gaierror, socket.herror, socket.timeout) as ex:
            Logger.error(unicode('Error in IMAP connection - %s' % (str(ex))))
            return

        pool = ThreadPool(5)

        while True:
            try:
                messages = self.get_messages()
            except (socket.error, socket.gaierror, socket.herror,
                    socket.timeout, ssl.SSLError) as ex:
                Logger.debug(unicode('Error in IMAP connection - %s' % (str(ex))))
                return

            if not messages:
                sleep(1)
                continue

            uids = messages.keys()
            args = [(uid, messages) for uid in uids]
            pool.map(push_email, args)
            pool.wait_completion()

            for uid in uids:
                if uid not in messages:
                    self._imap_conn.uid('store', uid, '+FLAGS', r'(\Deleted)')

            self._imap_conn.expunge()
            sleep(1)

    def get_messages(self):
        """ Get all new emails
        """
        response = {}
        _, data = self._imap_conn.uid('search', None, 'ALL')
        messages = data[0].split()

        Logger.debug(unicode('Still %d emails to fetch' % (len(messages))))

        for message_uid in messages[:50]:
            _, data = self._imap_conn.uid('fetch', message_uid, '(RFC822)')
            body = data[0][1]
            response[message_uid] = body

        return response


def get_imap_connection(host=None, port=None, user=None, passwd=None):
    """
        Connect to mailbox using IMAP
    """
    conn = IMAP4_SSL(host, port)
    conn.login(user, passwd)
    conn.select('INBOX')
    return conn


def main():
    """
        Main loop
    """
    fetcher = EmailFetcher()

    try:
        fetcher.run()
    except Exception as ex:
        Logger.error(unicode('Error while fetching emails - %s' % (str(ex))))
        sys.exit(0)


if __name__ == "__main__":

    main()
