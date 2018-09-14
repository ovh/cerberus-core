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
    Parsing template for *@axur.com
"""

import re

from abuse.parsers import Parser


def pretransform(content):

    pattern = r'Category\s*:\s*(.*)'
    search = re.search(pattern, content, re.IGNORECASE & re.MULTILINE)
    if search:
        return search.group()
    return content


TEMPLATE = {
    'fallback': False,
    'email': '*@axur.com',
    'regexp': {
        'ips': {
            'pattern': r'(?:IP\s*:\s*|IP\s*Address\s*:\s*)' + Parser.ipv4_re,
        },
        'urls': {
            'pattern': r'(?:Infringing\s*Material\s*:\s*|URL\s*:\s*|The\s*artifact\s*is\s*hosted\s*at\s*:\s*|We\s*detected\s*a\s*phishing\s*web\s*site\s*hosted\s*at\s*:\s*)' + Parser.url_re,
        },
        'fqdn': {
            'pattern': r'(?:Host\s*:\s*|the\s*domain\s*name|It\s*has\s*come\s*to\s*our\s*attention\s*that\s*the\s*website\s*|C&C\s*)(' + Parser.domain_re + '):*',
        },
        'category': {
            'pretransform': pretransform,
            'pattern': r'((.|\n|\r|\t)*)',
            'transform': True
        },
    },
}
