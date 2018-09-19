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
    Email parser for Cerberus
"""

from __future__ import unicode_literals

import glob
import imp
import os
import quopri
import re
import time

from base64 import b64decode
from datetime import datetime

import mailparser
import netaddr

from django.db.models import ObjectDoesNotExist

from ..models import Provider
from ..utils import networking


def load_templates():
    """
        Loads provider templates

        :rtype: dict:
        :return: All available templates
    """
    template_base = os.path.dirname(os.path.realpath(__file__))
    modules = glob.glob(os.path.join(template_base, "*.py"))
    files = [os.path.basename(f)[:-3] for f in modules]
    files = [f for f in files if f != "__init__"]
    templates = {}

    for template in files:
        infos = imp.load_source(template, os.path.join(template_base, template + ".py"))
        templates[infos.TEMPLATE["email"]] = infos.TEMPLATE

    return templates


class ParsedEmail(object):
    """
        A structured abuse email
    """

    def __init__(self, **kwargs):

        self.headers = kwargs.get("headers")
        self.provider = kwargs.get("provider")
        self.recipients = kwargs.get("recipients")
        self.subject = kwargs.get("subject")
        self.body = kwargs.get("body")
        self.date = kwargs.get("date")
        self.category = kwargs.get("category") or "Other"
        self.ips = kwargs.get("ips") or []
        self.urls = kwargs.get("urls") or []
        self.fqdn = kwargs.get("fqdn") or []
        self.attachments = kwargs.get("attachments") or []
        self.blacklisted = kwargs.get("blacklisted") or False
        self.applied_template = kwargs.get("applied_template")

    def clean_items(self):
        """
            Remove extra stuff from items
        """
        for attrib in ("urls", "ips", "fqdn"):
            cleaned = set()
            for item in getattr(self, attrib):
                try:
                    cleaned.add(clean_item(item, attrib))
                except UnicodeDecodeError:
                    continue
            setattr(self, attrib, list(cleaned))

        # If parsed ip/fqdn are present in url, only keeping url
        if self.urls:
            urls = " ".join(self.urls)
            valid = []
            for ip_addr in self.ips:
                if not re.search(Parser.proto_re + re.escape(ip_addr), urls, re.I):
                    valid.append(ip_addr)
            self.ips = valid
            valid = []
            for fqdn in self.fqdn:
                if not re.search(Parser.proto_re + re.escape(fqdn), urls, re.I):
                    valid.append(fqdn)
            self.fqdn = valid


def clean_item(item, attrib):
    """
        Remove extra stuff from item

        :param str item: A `cerberus.parsers.ParsedEmail` item
        :rtype: str
        :return: The cleaned item
    """
    item = item.strip()
    item = item.replace(" ", "")
    item = item.replace("\r\n", "")

    if attrib == "ips":
        # '038.140.010.024' -> '38.140.10.24'
        item = re.sub(r"(?<!\d)0+(?=\d)", "", item)
    elif attrib == "fqdn":
        item = item.rstrip(".")

    deobfuscate_url = {
        "https": re.compile(re.escape("hxxpx"), re.I),
        "http": re.compile(re.escape("hxxp"), re.I),
    }

    for key, reg in deobfuscate_url.iteritems():
        item = reg.sub(key, item)

    item = item.replace("[.]", ".")
    item = item.replace("[dot]", ".")
    item = item.replace("dot", ".")
    item = re.sub(r"([^:])/{2,}", r"\1/", item)
    item = item.split(",,")[0]
    return item


class Parser(object):
    """
        Generic email/text parser
    """

    email_templates = []
    email_re = re.compile(
        r"""((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))""",
        re.I,
    )

    valid_categories = [
        "Illegal",
        "Intrusion",
        "Malware",
        "Network Attack",
        "Other",
        "Phishing",
        "Spam",
        "Copyright",
        "Compromised",
    ]

    # Machine Learning powa ...
    category_pattern = {
        "Spam": r"spam|trackback|comment spam",
        "Intrusion": r"harvesting|crack|infected|defacement|scam|scan|bruteforce|bruteforcing|intrusion|login-attack|invalid user|login failed|access denied|pharming",
        "Malware": r"malware-attack|malware|virus|exploit|ransomware|spyware|drive-by|backconnect|botnet|c&c|proxy|malicious file",
        "Phishing": r"phish|phishing|portals|infected|defacement",
        "Network Attack": "behind the ip| attack|drdos|dos|ddos|newtwork attack|attacked|denial of service|rogue dns",
        "Copyright": r"copyright|dmca|infringement|infringed|piracy|logo|brand",
        "Illegal": r"legal|illegal|terrorism|racism|nazism|child abuse|child porn|child abuse|pedopornograph|pédopornograph",
    }

    providers_generic = {
        re.compile(
            r"(antipiracy-node[0-9]+@degban\.com)", re.I
        ): "antipiracy@degban.com",
        re.compile(
            r"(takedown-response\+[0-9]+@netcraft\.com)", re.I
        ): "*@netcraft.com",
        re.compile(r"([0-9]+@reports\.spamcop\.net)", re.I): "*@reports.spamcop.net",
        re.compile(
            r"(.*@copyright-compliance\.com)", re.I
        ): "*@copyright-compliance.com",
        re.compile(r"(.*@friendmts\.com)", re.I): "*@friendmts.com",
        re.compile(r"(.*@axur\.com)", re.I): "*@axur.com",
        re.compile(r"(.*@alpa\.asso\.fr)", re.I): "*@alpa.asso.fr",
    }

    ipv4 = r"(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:(?:\s*dot\s*|\s*\[\s*dot\s*\]\s*|\s*\.\s*|\s*\[\s*\.\s*\]\s*)(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}"

    proto_re = r"[a-zA-Z0-9\.\-]+\s*:\s*/\s*/\s*"
    user_pass_re = r"(?:\S+:\S+@)?"
    domain_re = r"[a-zA-Z0-9\.\-]+(?:\s*\.\s*|\s*\[\s*\.\s*\]\s*|\s*\[\s*dot\s*\]\s*|\s*dot\s*)(?:[a-z]{2,})\s*"
    port_re = r"(?::\d{2,5})?"
    path_re = r"""(?:/[^\s"'<>\]\)]*)?"""
    ipv4_re = r"((?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)(?:(?:\s*dot\s*|\s*\[\s*dot\s*\]\s*|\s*\.\s*|\s*\[\s*\.\s*\]\s*)(?:25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})"
    url_re = None
    blacklisted_networks = []

    def __init__(self):

        if not self.url_re:
            raise RuntimeError(
                "Parser not initialized, please call 'Parser.set_up(config)'"
            )

    @classmethod
    def set_up(cls, config=None):

        if not config:
            config = {}

        cls.fqdn_re = config.get("fqdn_re")
        if not cls.fqdn_re:
            cls.fqdn_re = r"(.*\.example\.com)"

        if config.get("blacklisted_providers") and isinstance(
            config["blacklisted_providers"], list
        ):
            cls.blacklisted_providers = config["blacklisted_providers"]

        if config.get("networks_to_ignore"):
            for network in config["networks_to_ignore"]:
                cls.blacklisted_networks.append(netaddr.IPNetwork(network))

        domain_to_ignore = config.get("domain_to_ignore")
        if not domain_to_ignore or not isinstance(domain_to_ignore, list):
            domain_to_ignore = ["example.com"]

        domain_to_ignore_re = (
            r"(?!" + r"|".join(domain_to_ignore).replace(".", r"\.") + r"\b)"
        )

        cls.url_re = (
            "("
            + cls.proto_re
            + cls.user_pass_re
            + "(?:"
            + cls.ipv4
            + "|"
            + domain_to_ignore_re
            + cls.domain_re
            + ")"
            + cls.port_re
            + cls.path_re
            + ")"
        )
        cls.email_templates = load_templates()

    @classmethod
    def is_ipaddr_ignored(cls, ip_str):
        """
            Check if the `ip_addr` is blacklisted

            :param str ip_str: The IP address
            :rtype: bool
            :return: If the ip_addr has to be ignored
        """
        ip_addr = netaddr.IPAddress(ip_str)

        for network in cls.blacklisted_networks:
            if network.netmask.value & ip_addr.value == network.value:
                return True
        return False

    @classmethod
    def get_template(cls, name, others=None):
        """
            Mail from some providers (spamhaus etc ...) are formatted
            For each provider, regex pattern extract useful informations
            The set of patterns are named template
            URL, IPS ...

            :param str name: The name of the template
            :param list others: list of other templates (to check collisions)
            :rtype: dict:
            :return: The corresponding parsing template if exists
        """
        template = None
        try:
            template = cls.email_templates[name]
            if others and template.get("colliding_providers"):
                for _name in others:
                    if _name in template["colliding_providers"]:
                        template = None
                        break
        except KeyError:
            for reg, val in cls.providers_generic.iteritems():
                if reg.match(name):
                    try:
                        template = cls.email_templates[val]
                        return template
                    except KeyError:
                        pass
        return template

    def parse_from_email(self, content):
        """
            Parse a raw email

            :param str content: The raw email
            :rtype: `cerberus.parsers.ParsedEmail`
            :return: The parsed email
        """
        email = mailparser.parse_from_string(content)
        provider = self._get_provider(email)
        recipients = "{} {}".format(
            " ".join([addr for _, addr in email.to_]), email.message.get("Cc")
        )

        parsed = ParsedEmail(
            headers=email.headers,
            subject=email.subject,
            body=email.body,
            date=int(time.mktime(utc2local(email.date).timetuple())),
            provider=provider,
            recipients=self.email_re.findall(recipients),
            attachments=decode_attachments(email.attachments),
            blacklisted=provider in self.blacklisted_providers,
        )

        # Add 'message/*' content to body
        parsed.body = "{}\n\n--- Forwarded email(s) ---\n{}".format(
            parsed.body,
            "\n\n--------".join(get_mime_message_type_contents(email.message)),
        )

        self._fetch_items(parsed)
        self._force_abuse_category(parsed)
        parsed.clean_items()

        return parsed

    def _fetch_items(self, parsed):

        content_to_parse = "{}\n\n{}".format(parsed.subject, parsed.body)

        # final order is [recipients, provider, keywords, default]
        templates = self._get_matching_templates(parsed, content_to_parse)

        for template in templates:
            self._apply_template(parsed, content_to_parse, template)
            if (
                any((parsed.urls, parsed.ips, parsed.fqdn))
                or template.get("fallback") is False
            ):
                break

        parsed.applied_template = template["email"]

        # Try attachments
        if not any((parsed.urls, parsed.ips, parsed.fqdn)):
            self._parse_attachments(parsed)

        # Remove unwanted ip_addr
        if parsed.ips:
            valid = []
            for ip_addr in parsed.ips:
                _ip = re.sub(r"(?<!\d)0+(?=\d)", "", ip_addr)
                if networking.is_valid_ipaddr(_ip) and not self.is_ipaddr_ignored(_ip):
                    valid.append(_ip)
            parsed.ips = valid

    def _apply_template(self, parsed, content, template):
        """
            Get all items (IP, URL) of a parsed
        """
        try:
            for key, val in template["regexp"].iteritems():
                if "pattern" in val:
                    if "pretransform" in val:
                        res = re.findall(
                            val["pattern"], val["pretransform"](content), re.I
                        )
                    else:
                        res = re.findall(val["pattern"], content, re.I)
                    if res:
                        if "transform" in val:
                            res = self._guess_category(res[0])
                        setattr(parsed, key, res)
                elif "value" in val:
                    setattr(parsed, key, val["value"])
        except AttributeError:
            pass

    def _guess_category(self, content):
        """
            Try to get parsed category with defined keywords
            (kind of machine learning/deep learning function, no ...?)

            :param str content: The content to parse
            :rtype: str
            :return: The category (or None if not identified)

        """
        if isinstance(content, tuple):
            text = content[0]
        else:
            text = content

        category = None
        last_count = 0
        for cat, pattern in self.category_pattern.iteritems():
            count = len(re.findall(pattern, text, re.I))
            if count > last_count:
                last_count = count
                category = cat

        return category

    def _force_abuse_category(self, parsed):

        category = parsed.category

        # Checking if a default category is set for this provider
        try:
            prov = Provider.objects.get(email=parsed.provider)
            if prov.defaultCategory_id:
                category = prov.defaultCategory_id
        except (KeyError, ObjectDoesNotExist):
            pass

        # If no category, checking if provider email match a generic provider
        if category not in self.valid_categories:
            for reg, val in self.providers_generic.iteritems():
                if reg.match(parsed.provider):
                    try:
                        prov = Provider.objects.get(email=val)
                        category = prov.defaultCategory_id or "Other"
                        break
                    except (KeyError, ObjectDoesNotExist):
                        category = "Other"
                        break
        # Still not ?
        if category not in self.valid_categories:
            category = "Other"

        parsed.category = category

    def _get_matching_templates(self, parsed, content):
        """
            Try to identify items/category with templates
            based on provider/recipients/keyword infos
        """
        template_names = [parsed.provider]
        if parsed.recipients:
            template_names = parsed.recipients + template_names

        for keyword in ("acns", "x-arf", "fail2ban", "feedback-report"):
            if keyword in content.lower():
                template_names.append(keyword)

        template_names.append("default")

        templates = []
        for candidate in template_names:
            template = self.get_template(candidate, others=template_names)
            if template:
                templates.append(template)

        return templates

    def _get_provider(self, email):

        try:
            for friendly, addr in email.from_:
                search = self.email_re.search(addr)
                if search:
                    return search.group().lower()
                search = self.email_re.search(friendly)
                if search:
                    return search.group().lower()
            if "api:" in email.from_[0][0]:
                return email.from_.replace("<", "").replace(">", "").lower()
        except:
            pass

        _from = email.message.get("From")
        if _from:
            return _from.replace("<", "").replace(">", "").lower()

        return "unknown@provider.com"

    def _parse_attachments(self, parsed_email):

        for keyword in ("x-arf", "feedback-report", "default"):
            template = self.get_template(keyword)
            for attachment in parsed_email.attachments:
                self._apply_template(parsed_email, attachment["content"], template)
                if any((parsed_email.urls, parsed_email.ips, parsed_email.fqdn)):
                    return


def get_mime_message_type_contents(message):
    """
        Need to have forwarded email / abuse report (message/rfc822, message/feedback-report) in body
    """
    contents = []
    for msg in message.walk():
        content_type = msg.get_content_type().lower()
        if not content_type.startswith("message/"):
            continue
        content = msg.get_payload(decode=True)
        if not content:
            content = msg.as_string()
        if content:
            contents.append(content.decode("utf-8"))

    return contents


def decode_attachments(attachments):

    _attachments = []

    for att in attachments:
        content = att["payload"]
        if att.get("binary"):
            if att["content_transfer_encoding"] == "base64":
                content = b64decode(content)
            elif att["content_transfer_encoding"] == "quoted-printable":
                content = quopri.decodestring(content)

        _attachments.append(
            {
                "content_type": att["mail_content_type"],
                "filename": att["filename"],
                "content": content,
            }
        )

    return _attachments


def utc2local(utc):

    try:
        epoch = time.mktime(utc.timetuple())
        offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
        return utc + offset
    except AttributeError:
        return datetime.now()
