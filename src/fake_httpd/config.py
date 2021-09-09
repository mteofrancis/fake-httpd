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

from mteo_util import to_str

# Default configuration settings
DEFAULT_CONFIG = {
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

  _parser = None
  _config = None

  ## {{{ Config.__init__()
  def __init__(self):
    self._parser = configparser.ConfigParser()
    self._config = {}
  ## }}}

  ## {{{ Config.__getitem__()
  def __getitem__(self, key):
    if key not in self._config:
      raise KeyError(key)
    return self._config[key]
  ## }}}

  ## {{{ Config.__setitem__()
  def __setitem__(self, key, value):
    self._config[key] = value
  ## }}}

  ## {{{ Config.from_dict()
  def from_dict(self, dict):
    defaults = DEFAULT_CONFIG

    for key in dict:
      if key not in defaults.keys():
        raise ConfigError(f"invalid configuration setting '{key}'")

      defaults_type = type(defaults[key]).__name__
      dict_type = type(dict[key]).__name__
      if defaults_type != dict_type:
        raise ConfigError(f"{key}: invalid type (expecting {defaults_type}, got {dict_type}")

    for key, value in dict.items():
      self._config[key] = value

    for key, value in defaults.items():
      if key in self._config:
        continue
      self._config[key] = value
  ## }}}

  ## {{{ Config.from_file()
  def from_file(self, path):
    defaults = DEFAULT_CONFIG

    try:
      self._parser.read(path)
    except configparser.Error as ex:
      raise ConfigError(to_str(ex))

    for section in self._parser.sections():
      if section == 'fake-httpd':
        continue
      raise ConfigError(f"{path}: invalid section '{section}'")

    for key, value in defaults.items():
      if key in self._parser['fake-httpd']:
        config_value = self._parser['fake-httpd'][key]
        defaults_type = type(defaults[key]).__name__
        config_type = type(config_value).__name__
        if defaults_type == 'int':
          self._config[key] = int(config_value)
        else:
          self._config[key] = config_value
      else:
        self._config[key] = defaults[key]
  ## }}}

  ## {{{ Config.items()
  def items(self):
    return self._config.items()
  ## }}}

## class Config }}}

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
