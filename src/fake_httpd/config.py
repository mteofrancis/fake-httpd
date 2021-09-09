#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# fake-httpd.git:/src/fake_httpd/config.py
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

import configparser

# Default configuration settings
CONFIG_DEFAULTS = {
  'home_dir': '/var/lib/fake-httpd',
  'log_dir': '/var/log/fake-httpd',
  'bind_address': '0.0.0.0',
  'bind_port': 80,
  'user': 'www-data',
  'group': 'www-data',
  'timeout': 30,
}

## {{{ class ConfigError

class ConfigError(Exception):

  message = None

  ## {{{ ConfigError.__init__()
  def __init__(self, message):
    self.message = message
  ## }}}

## class ConfigError }}}

## {{{ class Config

class Config:

  _config = None

  ## {{{ Config.__init__()
  def __init__(self):
    self._config = configparser.ConfigParser()
  ## }}}

  ## {{{ Config.from_dict()
  def from_dict(self, dict):
    for key in dict:
      if key in CONFIG_DEFAULTS.keys():
        continue
      raise ConfigError(f"invalid key '{key}'")

    self._config['fake-httpd'] = {}
    for key, value in dict.items():
      self._config['fake-httpd'][key] = str(value)
  ## }}}

  ## {{{ Config.from_file()
  def from_file(self, path):
    try:
      self._config.read(path)
    except configparser.Error as ex:
      raise ConfigError(str(ex))

    for section in self._config.sections():
      if section == 'fake-httpd':
        continue
      raise ConfigError(f"{path}: invalid section '{section}'")

    for key, value in CONFIG_DEFAULTS.items():
      if key in self._config['fake-httpd']:
        continue
      self._config['fake-httpd'][key] = value
  ## }}}

  ## {{{ Config.items()
  def items(self):
    return self._config['fake-httpd'].items()
  ## }}}

  ## {{{ Config.get()
  def get(self, name):
    return self._config['fake-httpd'][name]
  ## }}}

## class Config }}}

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
