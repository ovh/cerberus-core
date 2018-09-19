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
    Parsing template for cert-soc@lexsi.com
"""

from abuse.parsers import Parser

TEMPLATE = {
    "email": "cert-soc@lexsi.com",
    "fallback": False,
    "regexp": {
        "ips": {
            "pattern": r"(?:(?:Adresse\s*IP|IP address\(es\))\s*:\s*)" + Parser.ipv4_re
        },
        "urls": {
            "pattern": r"(?:contenus\s*manifestement\s*frauduleux\s*sur\s*|Site\s*concern.*\s*:\s*|at the following URL\s*:\s*)"
            + Parser.url_re
        },
        "category": {"pattern": r"((.|\n|\r|\t)*)", "transform": True},
    },
}
