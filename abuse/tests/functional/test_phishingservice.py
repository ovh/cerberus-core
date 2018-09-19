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
    Unit tests for phishing service default implementation
"""

from ...services.phishing import PhishingService
from ...tests.setup import CerberusTest


class TestDefaultPhishingImpl(CerberusTest):
    """
        Unit tests for phishing service
    """

    def test_ping_url(self):
        """
            Test ping_url
        """
        ping_response = PhishingService.ping_url("http://www.example.com/phishing")
        self.assertEqual(0, ping_response.score)
        self.assertEqual("200", ping_response.http_code)

    def test_get_screenshots(self):
        """
            Test get_screenshots
        """
        screenshots = PhishingService.get_screenshots("http://www.example.com/phishing")
        self.assertEqual(1, len(screenshots))
        self.assertEqual(
            "https://www.ovh.com/fr/news/logos/with-baseline/logo-ovh-avec-150DPI.png",
            screenshots[0]["location"],
        )
