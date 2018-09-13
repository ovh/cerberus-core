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


import socket
from urlparse import urlparse

import netaddr
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator, validate_ipv46_address

DNS_ERROR = {
    '-2': 'NXDOMAIN'
}


class NetworkOwnerHandler(object):

    networks = {
        'cloudflare': [
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '104.16.0.0/12',
            '108.162.192.0/18',
            '131.0.72.0/22',
            '141.101.64.0/18',
            '162.158.0.0/15',
            '172.64.0.0/13',
            '173.245.48.0/20',
            '188.114.96.0/20',
            '190.93.240.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17'
        ],
        'managed': []  # computed at setup
    }

    @classmethod
    def set_up(cls, managed_networks):

        cls.networks['managed'] = managed_networks
        for brand, network in cls.networks.iteritems():
            cls.networks[brand] = [netaddr.IPNetwork(net) for net in network]


def get_ip_network(ip_str):
    """
        Try to return the owner of the IP address (based on ips.py)

        :param str ip_str: The IP address
        :rtype: str
        :return: The owner if find else None
    """
    try:
        ip_addr = netaddr.IPAddress(ip_str)
    except (netaddr.AddrConversionError, netaddr.AddrFormatError):
        return None

    for brand, networks in NetworkOwnerHandler.networks.iteritems():
        for net in networks:
            if net.netmask.value & ip_addr.value == net.value:
                return brand
    return None


def is_valid_ipaddr(ip_addr):
    """
        Check if the `ip_addr` is a valid ipv4

        :param str ip_str: The IP address
        :rtype: bool
        :return: If the ip_addr is valid
    """
    try:
        validate_ipv46_address(ip_addr)
        return True
    except ValidationError:
        return False


def get_url_hostname(url):
    """
        Try to get domain for an url

        :param str url: The url to extract hostname
        :rtype: str
        :return: the hostname or None
    """
    try:
        validate = URLValidator(schemes=(
            'http', 'https', 'ftp', 'ftps', 'rtsp', 'rtmp'
        ))
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
        :return: the list of resolved IP address for given url
    """
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            socket.setdefaulttimeout(5)
            ips = socket.gethostbyname_ex(parsed.hostname)[2]
            return ips
    except (ValueError, socket.error, socket.gaierror,
            socket.herror, socket.timeout):
        pass


def get_ips_from_fqdn(fqdn):
    """
        Retrieve IPs from FQDN

        :param str fqdn: The FQDN to resolve
        :rtype: list
        :return: the list of resolved IP address for given FQDN
    """
    try:
        socket.setdefaulttimeout(5)
        ips = socket.gethostbyname_ex(fqdn)[2]
        return ips
    except (ValueError, socket.error, socket.gaierror,
            socket.herror, socket.timeout):
        return None


def get_reverses_for_item(item, nature='IP', replace_exception=False):
    """
        Try to get reverses infos for given item

        :param str item: Can be an IP address, a URL or a FQDN
        :param str nature: The nature of the item
        :param bool replace_exception: Replace by NXDOMAIN or TIMEOUT
        :rtype: dict
        :return: a dict containing reverse infos
    """
    hostname = None
    reverses = {}

    if nature == 'IP':
        reverses['ip'] = item
        try:
            validate_ipv46_address(item)
            reverses['ipReverse'] = socket.gethostbyaddr(item)[0]
            reverses['ipReverseResolved'] = socket.gethostbyname(reverses['ipReverse'])
        except (IndexError, socket.error, socket.gaierror, socket.herror,
                socket.timeout, TypeError, ValidationError):
            pass
    elif nature == 'URL':
        reverses['url'] = item
        parsed = urlparse(item)
        if parsed.hostname:
            hostname = parsed.hostname
    else:
        reverses['fqdn'] = item
        hostname = item

    if hostname:
        try:
            reverses['fqdn'] = hostname
            reverses['fqdnResolved'] = socket.gethostbyname(hostname)
            reverses['fqdnResolvedReverse'] = socket.gethostbyaddr(reverses['fqdnResolved'])[0]
        except socket.gaierror as ex:
            if replace_exception:
                try:
                    reverses['fqdnResolved'] = DNS_ERROR[str(ex.args[0])]
                except KeyError:
                    reverses['fqdnResolved'] = 'NXDOMAIN'
        except socket.timeout:
            if replace_exception:
                reverses['fqdnResolved'] = 'TIMEOUT'
        except (IndexError, TypeError, socket.error, socket.herror):
            pass

    return reverses
