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
    Defined Phishing Service abstract class
"""

import abc
from collections import namedtuple

PingResponse = namedtuple('Ping', ['score', 'http_code', 'direct_status', 'proxied_status', 'is_phishing'])


class PhishingServiceException(Exception):
    """
        Exception that must be raised by PhishingService implementations to ensure error are correctly handled.

        .. py:class:: PhishingServiceException
    """
    def __init__(self, message):
        super(PhishingServiceException, self).__init__(message)


class PhishingServiceBase(object):
    """
        Abstract class defining phishing services needed by Cerberus:

        - 'ping' an url
        - get screenshots for an url (for example taken by Selenium)
        - post feedback: is the url is really a phishing page or not (for example to improve a Machine Learning system)
        - block url: a way, your way, to block/remove a phishing url (https://github.com/ovh/phishing-mitigation for example)

        The only exception allowed to be raised is ..py:exception:: PhishingServiceException

    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def ping_url(self, url, country=None):
        """
            Ping given url

            :param str url: The url to ping.
            :param str country: A country, usefull for geo-phishing
            :return: A PingResponse object containing these infos:
                direct_status, proxied_status, http_code, score (0 for 'UP' to 100 for 'DOWN') and is_phishing (computed by your solution)
            :rtype: PingResponse
            :raises PhishingServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'ping_url'" % (cls))

    @abc.abstractmethod
    def get_screenshots(self, url, limit=10):
        """
            Get screenshots for given url (one url can have multiple screenshots)

            [{
                'timestamp': 1452706246,
                'location': 'https://your.screenshot.storage/example.png',
                'screenshotId': '123456',
                'phishingGrade': '0.9',  # Between 0 and 1 (0, not phishing, 1 phishing)
                'phishingGradeDetails': {
                    'category': 'PHISHING',  # Can be "LEGIT" or "PHISHING"
                    'grade': 0.1,  # Same as phishingGrade
                    'comment': 'no comment',
                },
                'score': 0,  # Between 0 and 100 (0, UP, 100, DOWN)
                'response': {
                    'directAccess': {
                        'statusCode': 200,
                        'headers': '200 OK\ncontent-length: 44\naccept-ranges: bytes\n ...',
                        'state': 'UP',
                    },
                    'proxyAccess': {
                        'proxyAddr': '1.2.3.4',
                        'statusCode': 200,
                        'headers': '200 OK\ncontent-length: 44\naccept-ranges: bytes\n ...',
                        'state': 'UP',
                    }
                }
            }]

            :param str url: The url.
            :param int limit: Limit the number of screenshots returned
            :return: A list containing screenshots infos
            :rtype: list
            :raises PhishingServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_screenshots'" % (cls))

    @abc.abstractmethod
    def is_screenshot_viewed(self, screenshot_id):
        """
            In get_screenshots, a screenshotId is returned for each screenshot.
            If your screenshotting API exposed this screenshot (as proof), it can
            be interesting to store if the screenshot have been viewed or not

            Returns something like :

            {
                'viewed': True,
                'views': [
                    {
                        'ip': '1.2.3.4',
                        'userAgent': 'curl/7.38.0',
                        'timestamp': 123456789,
                    },
                ],
            }

            or

            {
                'viewed': False,
                'views': [],
            }

            :param str screenshot_id : The uuid of the screenshot
            :return: Details about screenshot
            :rtype: dict
            :raises PhishingServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'is_screenshot_viewed'" % (cls))

    @abc.abstractmethod
    def post_feedback(self, screenshot_id, isphishing):
        """
            Post feedback

            :param str screenshot_id: The uuid of the screenshot
            :param bool isphishing: Yes or not it is a phishing url
            :raises PhishingServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'post_feedback'" % (cls))

    @abc.abstractmethod
    def block_url(self, url, report):
        """
            Block/remove a phishing url

            :param str url: The URL to block

            :raises PhishingServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'block_url'" % (cls))

    @abc.abstractmethod
    def get_http_headers(self, url):
        """
            Get url HTTP headers (like curl -I)

            Returns:

            {
                'url': 'https://www.ovh.com/fr/,
                'headers': 'HTTP/1.1 200 OK
                            Set-Cookie: a=R1837865839; path=/; expires=Sun, 12-Jun-2016 02:06:33 GMT
                            Set-Cookie: b=R2649533674; path=/; expires=Thu, 09-Jun-2016 14:55:03 GMT
                            Content-Type: text/html; charset=UTF-8
                            Cache-Control: max-age=600
                            Expires: Thu, 09 Jun 2016 13:59:02 GMT
                            Connection: close
                            ...,
                }
            }

            :param str url: The URL to block
            :return: Details about headers
            :rtype: dict

            :raises PhishingServiceException: if any error occur
        """
        cls = self.__class__.__name__
        raise NotImplementedError("'%s' object does not implement the method 'get_http_headers'" % (cls))
