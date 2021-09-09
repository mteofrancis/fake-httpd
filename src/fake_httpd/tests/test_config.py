#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# fake-httpd.git:/src/fake_httpd/tests/test_config.py
##

import os

import unittest

from ..config import (
  DEFAULT_CONFIG,
  Config,
  ConfigError,
)

class TestConfig(unittest.TestCase):

  ## {{{ TestConfig._assert_defaults()
  def _assert_defaults(self, config):
    self.assertTrue(config['home_dir'] == '/var/lib/fake-httpd')
    self.assertTrue(config['log_dir'] == '/var/log/fake-httpd')
    self.assertTrue(config['bind_address'] == '0.0.0.0')
    self.assertTrue(config['bind_port'] == 80)
    self.assertTrue(config['user'] == 'www-data')
    self.assertTrue(config['group'] == 'www-data')
    self.assertTrue(config['timeout'] == 30)
  ## }}}

  ## {{{ TestConfig.test_defaults()
  def test_defaults(self):
    config = Config()
    config.from_dict({})
    self._assert_defaults(config)
  ## }}}

  ## {{{ TestConfig.test_from_dict()
  def test_from_dict(self):
    config = Config()
    config.from_dict({'home_dir': '/var/lib/fake-httpd'})
    self._assert_defaults(config)
  ## }}}

  ## {{{ TestConfig.test_from_file()
  def test_from_file(self):
    config = Config()
    config.from_file(os.path.join(os.path.dirname(__file__), 'test.conf'))
    self._assert_defaults(config)
  ## }}}

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
