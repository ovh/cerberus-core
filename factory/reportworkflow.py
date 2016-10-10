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
    Factory module allowing users to inject their own abuse report processing.
"""

import importlib

from django.conf import settings

from worker.workflows.report.abstract import ReportWorkflowBase


class WrongReportWorkflowException(Exception):
    """
        Exception raised when provided report workflow implementation does not inherit of our interface.

        .. py:class:: WrongReportWorkflowException
    """
    def __init__(self, message):
        super(WrongReportWorkflowException, self).__init__(message)


class ReportWorkflowFactory(object):
    """
        This handy magical class provides an easy way to let users inject their own report workflow
        used in report processing (worker/report.py).
    """
    def __init__(self):

        self.registered_instances = []
        self.read_worflows_available()

    def read_worflows_available(self):
        """
            Read custom workflows implementation from settings
        """
        for workflow in settings.CUSTOM_REPORT_WORKFLOWS:
            class_object = self.get_impl_adapter_from_string(workflow)

            # Ensure the implementation really implements provided interface
            if not issubclass(class_object, ReportWorkflowBase):
                raise WrongReportWorkflowException(workflow)

            self.__register_impl(class_object)

    @staticmethod
    def get_impl_adapter_from_string(string):
        module_name, cls_name = string.rsplit('.', 1)
        return getattr(importlib.import_module(module_name), cls_name)

    def __register_impl(self, class_obj):
        self.registered_instances.append(class_obj())


if not hasattr(ReportWorkflowFactory, 'instance'):
    ReportWorkflowFactory.instance = ReportWorkflowFactory()
