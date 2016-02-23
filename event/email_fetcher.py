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

"""

import hashlib
import inspect
import os
import Queue
import socket
import ssl
import sys
from imaplib import IMAP4, IMAP4_SSL
from threading import Thread
from time import sleep

CURRENTDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PARENTDIR = os.path.dirname(CURRENTDIR)
sys.path.insert(0, PARENTDIR)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()

from django.conf import settings
from redis import Redis
from rq import Queue as rq_queue

from adapters.services.storage.abstract import StorageServiceException
from factory.factory import ImplementationFactory
from utils.logger import get_logger


Logger = get_logger(os.path.basename(__file__))
Worker = rq_queue(connection=Redis())

CHARSETS = ('iso-8859-1', 'iso-8859-15', 'utf-8', 'ascii', 'utf-16', 'windows-1252', 'cp850', 'iso-8859-11')
HOST = settings.EMAIL_FETCHER['host']
PORT = settings.EMAIL_FETCHER['port']
USER = settings.EMAIL_FETCHER['login']
PASS = settings.EMAIL_FETCHER['pass']


class FetchEmail(Thread):
    """
        Pop one email, save content to storage service
        and push a parsing task
    """
    def __init__(self, uid, email, queue):
        Thread.__init__(self)
        self._uid = uid
        self._email = email
        self._queue = queue

    def run(self):
        """
            Fetch email
            Push to Storage Service
            Add a worker task
        """
        filename = hashlib.sha256(self._email).hexdigest()
        Logger.debug(unicode('New mail - UID %s - HASH %s' % (self._uid, filename)), extra={'hash': filename})

        for chset in CHARSETS:
            try:
                self._email = self._email.decode(chset).encode('utf-8')
                break
            except UnicodeError:
                Logger.debug(str('error while decoding email with charset %s' % (chset,)))

        push_to_storage_service(filename, self._email)
        push_task_to_worker(filename, self._email)
        self._queue.get(self._uid)


def push_to_storage_service(filename, email):
    """ Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    with ImplementationFactory.instance.get_instance_of('StorageServiceBase', settings.GENERAL_CONFIG['email_storage_dir']) as cnx:
        try:
            cnx.read(filename)
            Logger.error(unicode('Email %s already in Storage Service' % (filename)))
            return
        except StorageServiceException:
            pass

    with ImplementationFactory.instance.get_instance_of('StorageServiceBase', settings.GENERAL_CONFIG['email_storage_dir']) as cnx:
        cnx.write(filename, email)
        Logger.info(unicode('Email %s pushed to Storage Service' % (filename)))


def push_task_to_worker(filename, email):
    """ Push parsing task to worker

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    Worker.enqueue(
        'report.create_from_email',
        email_content=email,
        filename=filename,
        timeout=3600,
    )
    Logger.info(unicode('Task for email %s successfully created' % (filename)))


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
        threads = []

        try:
            self._imap_conn = get_imap_connection(host=HOST, port=PORT, user=USER, passwd=PASS)
        except (IMAP4.error, IMAP4.abort, IMAP4.readonly) as ex:
            Logger.error(unicode('Error in IMAP connection - %s' % (str(ex))))
            return
        except (socket.error, socket.gaierror, socket.herror, socket.timeout) as ex:
            Logger.error(unicode('Error in IMAP connection - %s' % (str(ex))))
            return

        while True:
            try:
                messages = self.get_messages()
            except (socket.error, socket.gaierror, socket.herror, socket.timeout, ssl.SSLError) as ex:
                Logger.debug(unicode('Error in IMAP connection - %s' % (str(ex))))
                return

            queue = Queue.Queue()
            for uid in messages.keys():
                queue.put(uid)

            for uid, email in messages.iteritems():
                thread = FetchEmail(uid, email, queue)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            for uid in messages.keys():
                if uid not in queue.queue:
                    self._imap_conn.uid('store', uid, '+FLAGS', r'(\Deleted)')

            self._imap_conn.expunge()
            sleep(1)

    def get_messages(self):
        """ Get all new emails
        """
        response = {}
        _, data = self._imap_conn.uid('search', None, 'ALL')
        messages = data[0].split()

        for message_uid in messages[:20]:
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
