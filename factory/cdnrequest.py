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
    Factory module allowing users to inject their own implementation of our interface.
"""

import importlib

from django.conf import settings

from worker.workflows.cdnrequest.abstract import CDNRequestWorkflowBase


class WrongCDNRequestWorkflowException(Exception):
    """
        Exception raised when provided ticket workflow implementation does not inherit of our interface.

        .. py:class:: WrongCDNRequestWorkflowException
    """
    def __init__(self, message):
        super(WrongCDNRequestWorkflowException, self).__init__(message)


class CDNRequestWorkflowFactory(object):
    """
        This factory loads all CDNRequest classes declaredin settings
    """
    def __init__(self):

        self.registered_instances = []
        self.read_worflows_available()

    def read_worflows_available(self):
        """
            Read custom workflows implementation from settings
        """
        for workflow in settings.CUSTOM_CDN_REQUEST_WORKFLOWS:
            class_object = self.get_impl_adapter_from_string(workflow)

            # Ensure the implementation really implements provided interface
            if not issubclass(class_object, CDNRequestWorkflowBase):
                raise WrongCDNRequestWorkflowException(workflow)

            self.__register_impl(class_object)

    @staticmethod
    def get_impl_adapter_from_string(string):
        module_name, cls_name = string.rsplit('.', 1)
        return getattr(importlib.import_module(module_name), cls_name)

    def __register_impl(self, class_obj):
        self.registered_instances.append(class_obj())


if not hasattr(CDNRequestWorkflowFactory, 'instance'):
    CDNRequestWorkflowFactory.instance = CDNRequestWorkflowFactory()
