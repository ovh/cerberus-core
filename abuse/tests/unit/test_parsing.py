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
    Unit test for email parser
"""

import os

from ...parsers import Parser
from ...tests.setup import CerberusTest

FALLBACK_FALSE_TEMPLATE = {
    "email": "false@fallback.com",
    "fallback": False,
    "regexp": {
        "ips": {"pattern": r"(?:abuse\s*report\s*about\s*IP\s*:\s*)" + Parser.ipv4_re},
        "category": {"value": "Spam"},
    },
}

FALLBACK_TRUE_TEMPLATE = {
    "email": "true@fallback.com",
    "fallback": True,
    "regexp": {
        "ips": {"pattern": r"(?:abuse\s*report\s*about\s*IP\s*:\s*)" + Parser.ipv4_re},
        "category": {"value": "Spam"},
    },
}

NO_FALLBACK_SPECIFIED_TEMPLATE = {
    "email": "not_specified@fallback.com",
    "regexp": {
        "ips": {"pattern": r"(?:abuse\s*report\s*about\s*IP\s*:\s*)" + Parser.ipv4_re},
        "category": {"value": "Spam"},
    },
}


class TestParser(CerberusTest):
    """
        Unit tests for parser
    """

    samples = {}

    @classmethod
    def setUpClass(cls):

        cls.parser = Parser()
        cls.parser.email_templates[
            FALLBACK_TRUE_TEMPLATE["email"]
        ] = FALLBACK_TRUE_TEMPLATE
        cls.parser.email_templates[
            FALLBACK_FALSE_TEMPLATE["email"]
        ] = FALLBACK_FALSE_TEMPLATE

        for root, dirs, files in os.walk(
            os.path.abspath(os.path.dirname(__file__)) + "/../samples/"
        ):
            for name in files:
                filename = root + "/" + name
                with open(filename) as f:
                    cls.samples[name] = f.read()

    def test_get_sender_sample1(self):

        sample = self.samples["sample1"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual("me123@ovh.com", parsed_email.provider)

    def test_get_recipients_sample1(self):

        sample = self.samples["sample1"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertIn("abuse@ovh.net", parsed_email.recipients)
        self.assertNotIn("me123@ovh.com", parsed_email.recipients)

    def test_get_subject_sample1(self):

        sample = self.samples["sample1"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual("Encoding test", parsed_email.subject)

    def test_get_date_sample1(self):

        sample = self.samples["sample1"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1430342774, int(parsed_email.date))

    def test_get_template_sample1(self):

        sample = self.samples["sample1"]
        parsed_email = self.parser.parse_from_email(sample)
        template = self.parser.get_template(parsed_email.provider)
        self.assertEqual(None, template)
        self.assertEqual("default", parsed_email.applied_template)

    def test_get_parsed_email_sample1(self):

        sample = self.samples["sample1"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual("Other", parsed_email.category)
        self.assertEqual([], parsed_email.attachments)
        self.assertEqual(2, len(parsed_email.ips))
        self.assertNotIn("0.0.0.1", parsed_email.ips)
        self.assertNotIn("192.168.1.1", parsed_email.ips)
        self.assertIn("8.8.8.8", parsed_email.ips)
        self.assertEqual([], parsed_email.urls)
        self.assertEqual([], parsed_email.fqdn)

    def test_get_sender_sample2(self):

        sample = self.samples["sample2"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual("6301094139@reports.spamcop.net", parsed_email.provider)

    def test_get_recipients_sample2(self):

        sample = self.samples["sample2"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertIn("abuse@ovh.net", parsed_email.recipients)
        self.assertNotIn("6301094139@reports.spamcop.net", parsed_email.recipients)

    def test_get_subject_sample2(self):

        sample = self.samples["sample2"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertIn(
            "[SpamCop (213.251.151.160) id:6301094139]{SPAM 07.7} =?UTF-8?Q?Impor",
            parsed_email.subject,
        )

    def test_get_date_sample2(self):

        sample = self.samples["sample2"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1430342428, int(parsed_email.date))

    def test_get_parsed_email_sample2(self):

        sample = self.samples["sample2"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual("Spam", parsed_email.category)
        self.assertEqual([], parsed_email.attachments)
        self.assertEqual(1, len(parsed_email.ips))
        self.assertIn("213.251.151.160", parsed_email.ips)
        self.assertEqual([], parsed_email.urls)
        self.assertEqual([], parsed_email.fqdn)

    def test_get_sender_sample3(self):

        sample = self.samples["sample3"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual("newsletter@ipm.dhnet.be", parsed_email.provider)

    def test_get_recipients_sample3(self):

        sample = self.samples["sample3"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertIn("abuse@ovh.net", parsed_email.recipients)

    def test_get_date_sample3(self):

        sample = self.samples["sample3"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1433756294, int(parsed_email.date))

    def test_get_parsed_email_sample3(self):

        sample = self.samples["sample3"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual("Copyright", parsed_email.category)
        self.assertEqual([], parsed_email.attachments)
        self.assertEqual([], parsed_email.ips)
        self.assertIn(
            "http://re.ldh.be/image/1e/55755fc935709a87ac80251e.jpg", parsed_email.urls
        )
        self.assertEqual([], parsed_email.fqdn)

    def test_get_sender_sample4(self):

        sample = self.samples["sample4"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual("cpro@cpro.pt", parsed_email.provider)

    def test_get_recipients_sample4(self):

        sample = self.samples["sample4"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertIn("abuse@ovh.net", parsed_email.recipients)
        self.assertIn("cpro@cpro.pt", parsed_email.recipients)

    def test_get_date_sample4(self):

        sample = self.samples["sample4"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1432998071, int(parsed_email.date))

    def test_get_template_sample4(self):

        sample = self.samples["sample4"]
        parsed_email = self.parser.parse_from_email(sample)
        template = self.parser.get_template(parsed_email.provider)
        self.assertEqual(None, template)

    def test_get_parsed_email_sample4(self):

        sample = self.samples["sample4"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual("Copyright", parsed_email.category)
        self.assertNotIn(u'é"', parsed_email.body)
        self.assertEqual(3, len(parsed_email.attachments))
        self.assertIn("content", parsed_email.attachments[0])
        self.assertEqual([], parsed_email.ips)
        self.assertIn(
            "http://schemas.microsoft.com/office/2004/12/omml", parsed_email.urls
        )
        self.assertEqual(3, len(parsed_email.urls))
        self.assertEqual([], parsed_email.fqdn)

    def test_get_sender_sample5(self):

        sample = self.samples["sample5"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual("antipiracy-node320@degban.com", parsed_email.provider)

    def test_get_recipients_sample5(self):

        sample = self.samples["sample5"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertIn("abuse@ovh.net", parsed_email.recipients)
        self.assertIn("dmca@brazzers.com", parsed_email.recipients)

    def test_get_date_sample5(self):

        sample = self.samples["sample5"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1433749395, int(parsed_email.date))

    def test_get_template_sample5(self):

        sample = self.samples["sample5"]
        parsed_email = self.parser.parse_from_email(sample)
        template = self.parser.get_template(parsed_email.provider)
        self.assertTrue(1, len(template))

    def test_get_parsed_email_sample5(self):

        sample = self.samples["sample5"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual("Copyright", parsed_email.category)
        self.assertEqual(0, len(parsed_email.attachments))
        self.assertEqual([], parsed_email.ips)
        self.assertIn(
            "http://www.example.com/share/file/AAAAAAAAAAAAAAAAAAAAAAAAAA/",
            parsed_email.urls,
        )
        self.assertEqual(2, len(parsed_email.urls))
        self.assertEqual([], parsed_email.fqdn)

    def test_get_template(self):

        sample = self.samples["sample8"]
        parsed_email = self.parser.parse_from_email(sample)

        template = self.parser.get_template(parsed_email.provider)
        self.assertEqual(
            r"(?:Problem\s*:\s*)(.*)", template["regexp"]["category"]["pattern"]
        )

    def test_multiple_recipients(self):

        sample = self.samples["sample9"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual(4, len(parsed_email.recipients))
        self.assertIn("stephane@test.com", parsed_email.recipients)
        self.assertIn("some.inbox@isp.com", parsed_email.recipients)
        self.assertIn("other.inbox@isp.com", parsed_email.recipients)
        self.assertIn("ticket+VHFBLCTKDS.4c8c@abuse.isp.com", parsed_email.recipients)

    def test_multiple_with_cc(self):

        sample = self.samples["sample10"]
        parsed_email = self.parser.parse_from_email(sample)

        self.assertEqual(3, len(parsed_email.recipients))
        self.assertIn("abuse@isp.com", parsed_email.recipients)
        self.assertIn("me@provider.com", parsed_email.recipients)
        self.assertIn("me2@provider.com", parsed_email.recipients)

    def test_specific_template(self):

        providers = {
            "spamhaus": "notification@spamhaus.org",
            "nfoservers": "ddos-response@nfoservers.com",
            "lexsicom": "cert-soc@lexsi.com",
        }

        for file_name, template in providers.iteritems():
            sample = self.samples[file_name]
            parsed_email = self.parser.parse_from_email(sample)
            self.assertIn("1.2.3.4", parsed_email.ips)
            self.assertEqual(template, parsed_email.applied_template)

    def test_fallback_false(self):

        sample = self.samples["sample15"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual([], parsed_email.ips)

    def test_fallback_true(self):

        sample = self.samples["sample16"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1, len(parsed_email.ips))

    def test_no_fallback_specified(self):

        sample = self.samples["sample17"]
        parsed_email = self.parser.parse_from_email(sample)
        self.assertEqual(1, len(parsed_email.ips))
