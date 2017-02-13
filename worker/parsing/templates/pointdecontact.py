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
    Parsing template for contact@pointdecontact.net
"""

import re

from worker.parsing import regexp


def pretransform(content):

    pattern = r'(?:URL.*signal.*:\s*<\/b>\s*<br>(.|\n|\r|\t)*)(?:Bonjour)'
    search = re.search(pattern, content, re.IGNORECASE & re.MULTILINE)
    if search:
        return search.group()
    return content


TEMPLATE = {
    'fallback': False,
    'email': 'contact@pointdecontact.net',
    'regexp': {
        'urls': {
            'pretransform': pretransform,
            'pattern': regexp.URL,
        },
        'category': {
            'value': 'Illegal'
        },
    },
}
