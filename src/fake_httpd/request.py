#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# fake-httpd.git:/src/fake_httpd/request.py
##

## {{{ ---- [ Header ] -----------------------------------------------------------------------------

##
# Copyright (c) 2021 Francis M <francism@destinatech.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2.0 as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to:
#
#   Free Software Foundation
#   51 Franklin Street, Fifth Floor
#   Boston, MA 02110
#   USA
##

## }}} ---- [ Header ] -----------------------------------------------------------------------------

from mteo_util import (
  random_uuid,
  to_str,
)

from mteo_util.tlv import assert_type

from datetime import datetime

CRLF = b'\r\n'

# Valid HTTP request methods
VALID_REQUEST_METHODS = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT']

## {{{ class RequestError

class RequestError(Exception):

  message = None

  def __init__(self, message):
    self.message = message

## class RequestError }}}

## {{{ class InvalidRequestError

class InvalidRequestError(RequestError):

  def __init__(self, message):
    super().__init__(f'invalid request: {message}')

## class InvalidRequestError }}}

## {{{ class InvalidMethodError

class InvalidMethodError(RequestError):

  def __init__(self, method):
    super().__init__(f"invalid request method '{method}'")

## class InvalidRequestError }}}

## {{{ class InvalidHeaderError

class InvalidHeaderError(RequestError):

  def __init__(self, header):
    super().__init__(f"invalid header '{header}'")

## class InvalidRequestError }}}

## {{{ class Request

class Request:

  # Request UUID
  uuid = None

  # Raw request buffer/length
  raw = None
  length = None

  # UTC timestamp
  timestamp = None

  # Method, URI and HTTP version
  method = None
  uri = None
  version = None

  # Headers
  headers = None

  ## {{{ Request.__init__()
  def __init__(self):
    self.uuid = random_uuid()
    self.timestamp = datetime.utcnow()
    self.length = 0
  ## }}}

  def parse(self, buf):
    assert_type(buf, 'bytes', arg='buf')

    self.raw = buf
    self.length = len(buf)

    if self.raw.count(CRLF) < 1:
      raise RequestError('missing CRLF')

    request, headers = self.raw.split(CRLF, 1)

    try:
      to_str(request)
    except UnicodeError:
      raise RequestError('request contains invalid/non-printable characters')

    if not request:
      raise InvalidRequestError(f'empty request line')
    else:
      num_spaces = request.count(b' ')
      if num_spaces != 2:
        raise InvalidRequestError(f'request contains {num_spaces} seperators, 2 required')

    method, uri, version = request.split(b' ')

    # Valid request methods are uppercase letters
    if not method.isupper():
      raise InvalidMethodError(method)
    elif to_str(method) not in VALID_REQUEST_METHODS:
      raise InvalidMethodError(method)

    self.method = to_str(method)
    self.uri = to_str(uri)
    self.version = to_str(version)
    self.headers = {}

    if headers.count(CRLF) < 2:
      return

    # Remove trailing CRLFs
    headers = headers[:-4]

    parsed_headers = {}
    for header in headers.split(CRLF):
      try:
        to_str(header)
      except UnicodeError:
        raise RequestError('header contains invalid/non-printable characters')

      if header.count(b': ') < 1:
        raise InvalidHeaderError(header)

      name, value = header.split(b': ', 1)
      parsed_headers[to_str(name)] = to_str(value)

    self.headers = parsed_headers

  ## {{{ Request.to_dict()
  def to_dict(self):
    dict = {
      'uuid': self.uuid,
      'timestamp': self.timestamp,
    }

    if self.raw:
      dict['raw'] = self.raw

    if self.method:
      dict['method'] = self.method
      dict['uri'] = self.uri
      dict['version'] = self.version

    if self.headers:
      dict['headers'] = self.headers

    return dict
  ## }}}

## }}}

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
