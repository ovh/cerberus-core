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
    Default Implementation of Phishing Service

"""
from .base import PhishingServiceBase, PingResponse


class DefaultPhishingService(PhishingServiceBase):
    """
        Default Implementation of PhishingServiceBase
    """

    def __init__(self, config, logger=None):
        pass

    def ping_url(self, url, country=None, try_screenshot=True):
        """
            Ping given url

            :param str url: The url to ping.
            :param str country: A country, usefull for geo-phishing
            :param bool try_screenshot: Try to take a screenshot for the url
            :return: A dict containing these infos:
                direct_status, proxied_status, http_code, score (0 for 'UP' to 100 for 'DOWN')
                and is_phishing (computed by your solution)
            :rtype: dict
            :raises `cerberus.services.phishing.base.PhishingServiceException`
        """
        return PingResponse(0, "200", "OK", "OK", False)

    def get_screenshots(self, url, limit=10):
        """
            Get screenshots for given url
        """
        response = [
            {
                "timestamp": 1452706246,
                "location": u"https://www.ovh.com/fr/news/logos/with-baseline/logo-ovh-avec-150DPI.png",
                "screenshotId": u"123456",
                "phishingGrade": 0.0,
                "phishingGradeDetails": {
                    "category": "LEGIT",  # Can be "LEGIT" or "PHISHING"
                    "grade": 0.0,  # Same as phishingGrade
                    "comment": "no comment",
                },
                "score": 0,
                "response": {
                    "directAccess": {
                        "statusCode": 200,
                        "headers": u"200 OK\ncontent-length: 44\naccept-ranges: bytes\n ...",
                        "state": u"UP",
                    },
                    "proxyAccess": {
                        "proxyAddr": u"1.2.3.4",
                        "statusCode": 200,
                        "headers": u"200 OK\ncontent-length: 44\naccept-ranges: bytes\n ...",
                        "state": u"UP",
                    },
                },
            }
        ]
        return response

    def post_feedback(self, screenshot_id, isphishing):
        """
            Post feedback

            :param str screenshot_id: The uuid of the screenshot
            :param bool isphishing: Yes or not it is a phishing url
            :raises `cerberus.services.phishing.base.PhishingServiceException`
        """
        pass

    def is_screenshot_viewed(self, screenshot_id):
        """
            In get_screenshots, a screenshotId is returned for each screenshot.
            If your screenshotting API exposed this screenshot (as proof), it can
            be interesting to store if the screenshot have been viewed or not

            :param str screenshot_id : The uuid of the screenshot
            :return: If yes or not the screenshot has been viwed
            :rtype: bool
            :raises `cerberus.services.phishing.base.PhishingServiceException`
        """
        return {"viewed": False, "views": []}

    def block_url(self, url, report):
        """
            Block/remove a phishing url

            :param str url: The URL to block
            :param `abuse.models.Report` report: The associated report
            :raises `cerberus.services.phishing.base.PhishingServiceException`
        """
        pass

    def unblock_url(self, url):
        """
            Unblock a phishing url

            :param str url: The URL to block
            :raises `cerberus.services.phishing.base.PhishingServiceException`
        """
        pass

    def get_http_headers(self, url):
        """
            Get url HTTP headers (like curl -I)

            :param str url: The URL to block
            :return: Details about headers
            :rtype: dict
            :raises `cerberus.services.phishing.base.PhishingServiceException`
        """
        response = {"url": url, "headers": "200 OK\ncontent-length: 24187"}
        return response
