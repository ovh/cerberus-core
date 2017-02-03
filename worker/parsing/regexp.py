# -*- coding: utf8 -*-
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
    Regexp for parser
"""
import re

from django.conf import settings

IGNORE_DOMAIN = settings.PARSING['domain_to_ignore']
IGNORE_DOMAIN_RE = r'(?!' + r'|'.join(IGNORE_DOMAIN).replace('.', r'\.') + r'\b)'
IPV4_RE = r'(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:(?:\s*\.\s*|\s*\[\s*\.\s*\]\s*)(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}'
PROTO_RE = r'[a-zA-Z0-9\.\-]+\s*:\s*/\s*/\s*'
USER_PASS_RE = r'(?:\S+:\S+@)?'
DOMAIN_RE = r'[a-zA-Z0-9\.\-]+\s*\.\s*(?:[a-z]{2,})\s*'
PORT_RE = r'(?::\d{2,5})?'
PATH_RE = r"""(?:/[^\s"'<\]\)]*)?"""
IPV4 = '(' + IPV4_RE + ')'
FQDN = settings.PARSING['fqdn_re']
URL = '(' + PROTO_RE + USER_PASS_RE + '(?:' + IPV4_RE + '|' + IGNORE_DOMAIN_RE + DOMAIN_RE + ')' + PORT_RE + PATH_RE + ')'
EMAIL_RE = r"""((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))"""

EMAIL = re.compile(EMAIL_RE, re.IGNORECASE)

CATEGORY = {
    'Spam': r'spam|trackback|comment spam',
    'Intrusion': r'harvesting|crack|infected|defacement|scam|scan|bruteforce|bruteforcing|intrusion|login-attack|invalid user|login failed|access denied',
    'Malware': r'malware-attack|malware|virus|exploit|ransomware|spyware|drive-by|backconnect|botnet',
    'Phishing': r'phish|phishing|portals|infected|defacement',
    'Network Attack': 'behind the ip| attack|drdos|dos|ddos|newtwork attack|attacked|denial of service',
    'Copyright': r'copyright|dmca|infringement|infringed|piracy|logo|brand',
    'Illegal': r'legal|illegal|terrorism|racism|nazism|child abuse|child porn|pedopornography',
}

RECIPIENT = re.compile(settings.EMAIL_FETCHER['cerberus_re'], re.IGNORECASE)
DEOBFUSCATE_URL = {
    'https': re.compile(re.escape('hxxpx'), re.IGNORECASE),
    'http': re.compile(re.escape('hxxp'), re.IGNORECASE),
}

PROVIDERS_GENERIC = {
    re.compile(r'(antipiracy-node[0-9]+@degban\.com)', re.IGNORECASE): 'antipiracy@degban.com',
    re.compile(r'(takedown-response\+[0-9]+@netcraft\.com)', re.IGNORECASE): '*@netcraft.com',
    re.compile(r'([0-9]+@reports\.spamcop\.net)', re.IGNORECASE): '*@reports.spamcop.net',
    re.compile(r'(.*@copyright-compliance\.com)', re.IGNORECASE): '*@copyright-compliance.com',
    re.compile(r'(.*@alpa\.asso\.fr)', re.IGNORECASE): '*@alpa.asso.fr',
}

ACNS_PROOF = re.compile(r'(?:Dear Sir or Madam|On behalf of)(\n|.|\s)*?(<|---\s*Start)', re.MULTILINE)
