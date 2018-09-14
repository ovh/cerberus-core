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
    Parsing template for soc@phishlabs.com
"""

from abuse.parsers import Parser


def pretransform(content):

    content = content.replace('hXXps ', 'https://')
    content = content.replace('hXXp ', 'http://')
    content = content.replace(' [dot] ', '.')
    content = content.replace('[dot]', '.')
    return content


TEMPLATE = {
    'email': 'soc@phishlabs.com',
    'regexp': {
        'ips': {
            'pattern': r'(?:Associated\s*IP\s*Address\s*:\s*)' + Parser.ipv4_re,
        },
        'urls': {
            'pretransform': pretransform,
            'pattern': r'(?:The\s*following\s*URLs\s*are\s*some\s*components\s*of\s*this\s*phishing\s*attack\s*:\s*)' + Parser.url_re,
        },
        'category': {
            'pattern': r'((.|\n|\r|\t)*)',
            'transform': True
        },
    },
}
