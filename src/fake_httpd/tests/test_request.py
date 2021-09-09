#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# fake-httpd.git:/src/fake_httpd/tests/test_request.py
##

import os

import unittest

from ..request import (
  Request,
  RequestError,
)

from mteo_util import (
  to_str,
  ByteBuffer,
)

CRLF = b'\r\n'

class TestRequest(unittest.TestCase):

  ## {{{ TestRequest.test_invalid_requests()
  def test_invalid_requests(self):
    with self.assertRaisesRegex(RequestError, 'missing CRLF'):
      request = Request()
      request.parse(b'')

    with self.assertRaises(RequestError):
      request = Request()
      request.parse(CRLF)

    with self.assertRaises(RequestError):
      request = Request()
      request.parse(CRLF * 2)
  ## }}}

  ## {{{ TestRequest.test_garbage_request()
  def test_garbage_request(self):
    with self.assertRaisesRegex(RequestError, 'non-printable'):
      garbage = None
      while True:
        garbage = os.urandom(256)
        if CRLF not in garbage:
          break

      request = Request()
      request.parse(garbage + CRLF)
  ## }}}

  ## {{{ TestRequest.test_parse()
  def test_parse(self):
    buf = ByteBuffer(
      b'GET / HTTP/1.1\r\n' +
      b'Host: beef.core.destinatech\r\n' +
      b'Connection: keep-alive\r\n' +
      b'Cache-Control: max-age=0\r\n'
      b'DNT: 1\r\n'
      b'Upgrade-Insecure-Requests: 1\r\n' +
      b'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36\r\n' +
      b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n' +
      b'Accept-Encoding: gzip, deflate\r\n' +
      b'Accept-Language: en-US,en;q=0.9\r\n'
      b'\r\n'
    )

    request = Request()
    request.parse(buf.value())

    self.assertTrue(request.method == 'GET')
    self.assertTrue(request.uri == '/')
    self.assertTrue(request.version == 'HTTP/1.1')
    self.assertTrue(len(request.headers) == 9)
    self.assertTrue(request.headers['Host'] == 'beef.core.destinatech')
    self.assertTrue(request.headers['DNT'] == '1')
    self.assertTrue('Connection' in request.headers)
    self.assertTrue('Cache-Control' in request.headers)
    self.assertTrue('Upgrade-Insecure-Requests' in request.headers)
    self.assertTrue('User-Agent' in request.headers)
    self.assertTrue('Accept' in request.headers)
    self.assertTrue('Accept-Encoding' in request.headers)
    self.assertTrue('Accept-Language' in request.headers)
  ## }}}

  ## {{{ TestRequest.test_parse_no_headers()
  def test_parse_no_headers(self):
    buf = b'GET / HTTP/1.1\r\n\r\n'

    request = Request()
    request.parse(buf)

    self.assertTrue(request.method == 'GET')
    self.assertTrue(request.uri == '/')
    self.assertTrue(request.version == 'HTTP/1.1')
    self.assertTrue(len(request.headers) == 0)
  ## }}}

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
