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
import inspect

from django.conf import settings

from api.controllers.scheduling.abstract import TicketSchedulingAlgorithmBase
from worker.hooks.abstract import WorkflowHookBase


class WrongImplementationException(Exception):
    """
        Exception raised when provided implementation does not inherit of our interface.

        .. py:class:: WrongImplementationException
    """
    def __init__(self, message):
        super(WrongImplementationException, self).__init__(message)


class WrongHookException(Exception):
    """
        Exception raised when provided hook implementation does not inherit of our interface.

        .. py:class:: WrongHookException
    """
    def __init__(self, message):
        super(WrongHookException, self).__init__(message)


class WrongAlgoException(Exception):
    """
        Exception raised when provided ticket scheduling alogrithm implementation does not inherit of our interface.

        .. py:class:: WrongAlgoException
    """
    def __init__(self, message):
        super(WrongAlgoException, self).__init__(message)


class ImplementationNotFoundException(Exception):
    """
        Exception raised when requested implementation has not been provided by user configuration.

        .. py:class:: ImplementationNotFoundException
    """
    def __init__(self, message):
        super(ImplementationNotFoundException, self).__init__(message)


class ImplementationFactory(object):
    """
        This handy magical class provides an easy way to let users inject their own implementations of
        business/data access classes in the application by reading the configuration and instantiating
        the object at runtime.
    """

    def __init__(self):

        self._registered_implementations = {}
        self._registered_instances = {}

        self.read_custom_implementations()

    def get_instance_of(self, string, *args):
        """
            Spawn a new instance of a class, passing to the constructor provided args.

            :param str string: Whished class instance identifier
            :param array args: Arguments to passed to the class constructor
            :return: A new instance of the requested class
            :raises ImplementationNotFoundException: No implementation match passed identifier
        """
        if string not in self._registered_implementations:
            raise ImplementationNotFoundException(string)

        return self._registered_implementations[string](*args)

    def get_singleton_of(self, string):
        """
            Still return the same instance of a given class.

            :param str string: Wished class instance identifier
            :return: The only instance of the requested class
            :raises ImplementationNotFoundException: No implementation match passed identifier
        """
        if string not in self._registered_instances:
            self._registered_instances[string] = self.get_instance_of(string)

        return self._registered_instances[string]

    def is_implemented(self, string):
        """
            Return if base class is implemented.

            :param str string: Class instance identifier
        """
        return string in self._registered_implementations

    def read_custom_implementations(self):
        """
            Read custom implementation from settings
        """
        for impl in settings.CUSTOM_IMPLEMENTATIONS:
            class_object = self.get_impl_adapter_from_string(impl)
            class_base = self.get_base_adapter(class_object)

            # Ensure the implementation really implements provided interface
            if not class_base or not issubclass(class_object, class_base):
                raise WrongImplementationException(impl)

            self.__register_impl(class_base, class_object)

    @staticmethod
    def get_impl_adapter_from_string(string):
        module_name, cls_name = string.rsplit('.', 1)
        return getattr(importlib.import_module(module_name), cls_name)

    @staticmethod
    def get_base_adapter(class_obj):
        ancestors = inspect.getmro(class_obj)
        for cls in ancestors:
            if cls.__module__.startswith('adapters'):
                return cls

        return None

    def __register_impl(self, base, class_obj):
        self._registered_implementations[base.__name__] = class_obj


class ReportWorkflowHookFactory(object):
    """
        This handy magical class provides an easy way to let users inject their own report workflow hook
        used in report processing (worker/report.py).
    """
    def __init__(self):

        self.registered_hook_instances = set()
        self.read_hooks_available()

    def read_hooks_available(self):
        """
            Read custom hooks implementation from settings
        """
        for hook in settings.CUSTOM_WORKFLOW_HOOKS:
            class_object = self.get_impl_adapter_from_string(hook)

            # Ensure the implementation really implements provided interface
            if not issubclass(class_object, WorkflowHookBase):
                raise WrongHookException(hook)

            self.__register_impl(class_object)

    @staticmethod
    def get_impl_adapter_from_string(string):
        module_name, cls_name = string.rsplit('.', 1)
        return getattr(importlib.import_module(module_name), cls_name)

    def __register_impl(self, class_obj):
        self.registered_hook_instances.add(class_obj())


class TicketSchedulingAlgorithmFactory(object):
    """
        This handy magical class provides an easy way to let users inject their own ticket scheduling algorithms
        for API (see `api.controllers.TicketsController.get_todo_tickets`)
    """
    def __init__(self):

        self._registered_instances = {}
        self.read_algorithms_available()

    def get_instance_of(self, string, *args):
        """
            Spawn a new instance of a class, passing to the constructor provided args.

            :param str string: Whished class instance identifier
            :param array args: Arguments to passed to the class constructor
            :return: A new instance of the requested class
            :raises ImplementationNotFoundException: No implementation match passed identifier
        """
        if string not in self._registered_instances:
            raise ImplementationNotFoundException(string)

        return self._registered_instances[string](*args)

    def get_singleton_of(self, string):
        """
            Still return the same instance of a given class.

            :param str string: Wished class instance identifier
            :return: The only instance of the requested class
            :raises ImplementationNotFoundException: No implementation match passed identifier
        """
        if string not in self._registered_instances:
            self._registered_instances[string] = self.get_instance_of(string)

        return self._registered_instances[string]

    def read_algorithms_available(self):
        """
            Read custom algorithms implementation from settings
        """
        for algo in settings.CUSTOM_SCHEDULING_ALGORITHMS:
            class_object, class_name = self.get_impl_adapter_from_string(algo)

            # Ensure the implementation really implements provided interface
            if not issubclass(class_object, TicketSchedulingAlgorithmBase):
                raise WrongAlgoException(algo)

            self.__register_impl(class_name, class_object)

    @staticmethod
    def get_impl_adapter_from_string(string):
        module_name, cls_name = string.rsplit('.', 1)
        return getattr(importlib.import_module(module_name), cls_name), cls_name

    def __register_impl(self, name, class_obj):
        self._registered_instances[name] = class_obj()


# Before instantiate the singleton, check it has not already been done.
if not hasattr(ImplementationFactory, 'instance'):
    ImplementationFactory.instance = ImplementationFactory()

if not hasattr(ReportWorkflowHookFactory, 'instance'):
    ReportWorkflowHookFactory.instance = ReportWorkflowHookFactory()

if not hasattr(TicketSchedulingAlgorithmFactory, 'instance'):
    TicketSchedulingAlgorithmFactory.instance = TicketSchedulingAlgorithmFactory()
