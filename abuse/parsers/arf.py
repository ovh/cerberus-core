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
    Generic template for Abuse Reporting Format (ARF)
"""

from abuse.parsers import Parser

TEMPLATE = {
    'email': 'feedback-report',
    'fallback': True,
    'regexp': {
        'ips': {
            'pattern': r'(?:Source-IP\s*:\s*)' + Parser.ipv4_re,
        },
        'urls': {
            'pattern': r'(?:Reported-URI\s*:\s*)' + Parser.url_re,
        },
        'fqdn': {
            'pattern': r'(?:Reported-Domain\s*:\s*)' + Parser.fqdn_re,
        },
        'category': {
            'pattern': r'(?:Feedback-Type\s*:\s*)(.*)',
            'transform': True
        },
    },
}
