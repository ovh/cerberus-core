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
    Init for utils
"""

import netaddr

from django.conf import settings

import ips
import utils

for key, val in ips.IPS_NETWORKS.iteritems():
    utils.IPS_NETWORKS[key] = []
    for network in val:
        utils.IPS_NETWORKS[key].append(netaddr.IPNetwork(network))

for network in settings.PARSING['networks_to_ignore']:
    utils.BLACKLISTED_NETWORKS.append(netaddr.IPNetwork(network))
