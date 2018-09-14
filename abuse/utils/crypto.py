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
    Crypto utils for Cerberus
"""

import base64

from cryptography.fernet import Fernet, InvalidSignature, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoException(Exception):
    """
        CryptoException
    """
    def __init__(self, message):
        super(CryptoException, self).__init__(message)


class CryptoHandler(object):
    """
        Symmetric crypto for api token
    """
    _salt = None
    _kdf = None
    _key = None
    _fernet = None

    @classmethod
    def set_up(cls, secret):

        _secret = bytes(secret)
        cls._salt = _secret
        cls._kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=cls._salt,
            iterations=100000,
            backend=default_backend()
        )
        cls._key = base64.urlsafe_b64encode(cls._kdf.derive(_secret))
        cls._fernet = Fernet(cls._key)

    @classmethod
    def encrypt(cls, data):
        """
            Symmetric encryption using django's secret key
        """
        try:
            encrypted = cls._fernet.encrypt(data)
            return encrypted
        except (InvalidSignature, InvalidToken):
            raise CryptoException('unable to encrypt data')

    @classmethod
    def decrypt(cls, data):
        """
            Symmetric decryption using django's secret key
        """
        try:
            encrypted = cls._fernet.decrypt(data)
            return encrypted
        except (InvalidSignature, InvalidToken):
            raise CryptoException('unable to decrypt data')
