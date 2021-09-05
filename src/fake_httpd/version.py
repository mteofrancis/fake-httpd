#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# fake-httpd.git:/version.py
##

# Major version number
MAJOR = 0

# Minor version number
MINOR = 0

# Patch level
PATCH = 2

# Extra version information
EXTRA = 'rc3'

def get():
  return f'{MAJOR}.{MINOR}.{PATCH}{EXTRA}'

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
