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
    Utils for worker
"""

import base64
import json
import os
import re
import socket
from time import sleep
from urlparse import urlparse

import chardet
import html2text
import netaddr
import requests
from cryptography.fernet import Fernet, InvalidSignature, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator, validate_ipv46_address
from redis import ConnectionError as RedisError
from redis import Redis
from requests.exceptions import (ChunkedEncodingError, ConnectionError,
                                 HTTPError, Timeout)
from rq import Queue
from rq_scheduler import Scheduler
from simplejson import JSONDecodeError

from abuse.models import User
from logger import get_logger

Logger = get_logger(os.path.basename(__file__))

CHARSETS = ('iso-8859-1', 'iso-8859-15', 'ascii', 'utf-16', 'windows-1252', 'cp850', 'iso-8859-11')
CERBERUS_USERS = User.objects.all().values_list('username', flat=True)

IPS_NETWORKS = {}
BLACKLISTED_NETWORKS = []

queue = Queue(connection=Redis())
scheduler = Scheduler(connection=Redis())

redis = Redis(
    host=settings.REDIS['host'],
    port=settings.REDIS['port'],
    password=None,
    db=0,
)

html2text.ignore_images = True
html2text.images_to_alt = True
html2text.ignore_links = True


class CryptoException(Exception):
    """
        CryptoException
    """
    def __init__(self, message):
        super(CryptoException, self).__init__(message)


class Crypto(object):
    """
        Symmetric crypto for token
    """
    def __init__(self):

        self._salt = settings.SECRET_KEY
        self._kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend()
        )
        self._key = base64.urlsafe_b64encode(self._kdf.derive(settings.SECRET_KEY))
        self._fernet = Fernet(self._key)

    def encrypt(self, data):
        """
            Symmetric encryption using django's secret key
        """
        try:
            encrypted = self._fernet.encrypt(data)
            return encrypted
        except (InvalidSignature, InvalidToken):
            raise CryptoException('unable to encrypt data')

    def decrypt(self, data):
        """
            Symmetric decryption using django's secret key
        """
        try:
            encrypted = self._fernet.decrypt(data)
            return encrypted
        except (InvalidSignature, InvalidToken):
            raise CryptoException('unable to decrypt data')


class RequestException(Exception):
    """
        RequestException
    """
    def __init__(self, message, code):
        super(RequestException, self).__init__(message)
        self.code = code


def request_wrapper(url, auth=None, params=None, as_json=False, method='POST', headers=None, timeout=30):
    """
        Python-requests wrapper
    """
    request = None
    func_params = {
        'headers': headers,
        'auth': auth,
        'params': params,
        'data': params,
        'verify': True,
        'timeout': timeout,
    }

    max_tries = 3  # Because sometimes network or backend is instable (TCP RST, HTTP 500 etc ...)
    for retry in xrange(max_tries):
        try:
            if method == 'GET':
                func_params.pop('data', None)
            else:
                func_params.pop('params', None)

            request = getattr(requests, method.lower())(url, **func_params)
            request.raise_for_status()
            request.connection.close()
            if as_json:
                return request.json()
            return request
        except HTTPError as ex:
            if 500 <= int(ex.response.status_code) <= 599:
                if retry == max_tries - 1:
                    raise RequestException(__get_request_exception_message(request, url, params, ex), ex.response.status_code)
                else:
                    sleep(1)
            else:
                raise RequestException(__get_request_exception_message(request, url, params, ex), ex.response.status_code)
        except Timeout as ex:
            raise RequestException(__get_request_exception_message(request, url, params, ex), None)
        except (ChunkedEncodingError, ConnectionError, JSONDecodeError) as ex:
            if retry == max_tries - 1:
                raise RequestException(__get_request_exception_message(request, url, params, ex), None)
            else:
                sleep(1)


def __get_request_exception_message(request, url, params, exception):
    """
        Try to extract message from requests exeption
    """
    try:
        data = request.json()
        message = data['message']
    except (AttributeError, KeyError, JSONDecodeError, NameError, TypeError):
        message = str(exception)

    Logger.warning(unicode('error while fetching url %s, %s : %s' % (url, params, message)))
    return message


def get_url_hostname(url):
    """
        Try to get domain for an url

        :param str url: The url to extract hostname
        :rtype: str
        :returns: the hostname or None
    """
    try:
        validate = URLValidator()
        validate(url)
    except (ValueError, ValidationError):
        return None

    parsed = urlparse(url)
    return parsed.hostname


def get_ips_from_url(url):
    """
        Retrieve IPs from url

        :param str url: The url to resolve
        :rtype: list
        :returns: the list of resolved IP address for given url
    """
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            socket.setdefaulttimeout(5)
            ips = socket.gethostbyname_ex(parsed.hostname)[2]
            return ips
    except (ValueError, socket.error, socket.gaierror, socket.herror, socket.timeout):
        pass


def get_ips_from_fqdn(fqdn):
    """
        Retrieve IPs from FQDN

        :param str fqdn: The FQDN to resolve
        :rtype: list
        :returns: the list of resolved IP address for given FQDN
    """
    try:
        socket.setdefaulttimeout(5)
        ips = socket.gethostbyname_ex(fqdn)[2]
        return ips
    except (ValueError, socket.error, socket.gaierror, socket.herror, socket.timeout):
        return None


def get_reverses_for_item(item, nature='IP'):
    """
        Try to get reverses infos for given item

        :param str item: Can be an IP address, a URL or a FQDN
        :param str nature: The nature of the item
        :rtype: dict
        :returns: a dict containing reverse infos
    """
    hostname = None
    reverses = {}

    if nature == 'IP':
        reverses['ip'] = item
        try:
            validate_ipv46_address(item)
            reverses['ipReverse'] = socket.gethostbyaddr(item)[0]
            reverses['ipReverseResolved'] = socket.gethostbyname(reverses['ipReverse'])
        except (IndexError, socket.error, socket.gaierror, socket.herror, socket.timeout, TypeError, ValidationError):
            pass
    elif nature == 'URL':
        reverses['url'] = item
        parsed = urlparse(item)
        if parsed.hostname:
            hostname = parsed.hostname
    else:
        hostname = item

    if hostname:
        try:
            reverses['fqdn'] = hostname
            reverses['fqdnResolved'] = socket.gethostbyname(hostname)
            reverses['fqdnResolvedReverse'] = socket.gethostbyaddr(reverses['fqdnResolved'])[0]
        except (socket.gaierror, socket.error, socket.timeout, socket.herror, IndexError, TypeError):
            pass
    return reverses


def push_notification(data, user=None):
    """
        Push notification to Cerberus user(s)

        :param dict data: The content of the notification
    """
    if not user:
        notif_queues = ['cerberus:notification:%s' % (username) for username in CERBERUS_USERS]
    else:
        notif_queues = ['cerberus:notification:%s' % (user.username)]

    for notif_queue in notif_queues:
        try:
            redis.rpush(
                notif_queue,
                json.dumps(data),
            )
        except RedisError:
            pass


def get_user_notifications(username, limit=3):
    """
        Get notifications for given user

        :param str username: The username of the user
        :param int limit: The number of notifications to return
        :rtype: list
        :returns: A list of dict
    """
    notification_queue = 'cerberus:notification:%s' % (username)
    response = []

    if not limit:
        return response

    for _ in xrange(0, limit):
        if redis.llen(notification_queue) == 0:
            break
        notification = redis.blpop(notification_queue)[1]
        response.append(json.loads(notification))

    return response


def dehtmlify(body):
    """
        Try to dehtmlify a text

        :param str body: The html content
        :rtype: str
        :returns: The dehtmlified content
    """
    html = html2text.HTML2Text()
    html.body_width = 0
    body = html.handle(body.replace('\r\n', '<br/>'))
    body = re.sub(r'^(\s*\n){2,}', '\n', body, flags=re.MULTILINE)
    return body


def decode_every_charset_in_the_world(content, supposed_charset=None):
    """
        Try to detect encoding.
        If already in unicode, no need to go further (btw, a caught exception is raised.)

        :param str content: The content to decode
        :param str supposed_charset: A supposed encoding for given content
        :rtype: str
        :returns: The decoded content
    """
    try:
        guessed_charset = chardet.detect(content)['encoding']
    except ValueError:
        return content

    if supposed_charset:
        charsets = ['utf-8', supposed_charset, guessed_charset] + list(CHARSETS)
    else:
        charsets = ['utf-8', guessed_charset] + list(CHARSETS)

    charsets = sorted(set(charsets), key=charsets.index)

    for chset in charsets:
        try:
            return content.decode(chset)
        except (LookupError, UnicodeError, UnicodeDecodeError, TypeError):
            continue


def get_ip_network(ip_str):
    """
        Try to return the owner of the IP address (based on ips.py)

        :param str ip_str: The IP address
        :rtype: str
        :returns: The owner if find else None
    """
    try:
        ip_addr = netaddr.IPAddress(ip_str)
    except (netaddr.AddrConversionError, netaddr.AddrFormatError):
        return None

    for brand, networks in IPS_NETWORKS.iteritems():
        for net in networks:
            if net.netmask.value & ip_addr.value == net.value:
                return brand
    return None


def is_ipaddr_ignored(ip_str):
    """
        Check if the `ip_addr` is blacklisted

        :param str ip_str: The IP address
        :rtype: bool
        :returns: If the ip_addr has to be ignored
    """
    ip_addr = netaddr.IPAddress(ip_str)

    for network in BLACKLISTED_NETWORKS:
        if network.netmask.value & ip_addr.value == network.value:
            return True
    return False
