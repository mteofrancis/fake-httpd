#!/usr/bin/env python
# -*- coding: utf-8 -*-

##
# fake-httpd.git:/src/fake-httpd/main.py
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

## {{{ ---- [ Imports ] ----------------------------------------------------------------------------

import os
import sys

import pwd
import grp

from mteo_util import (
  caller,
  index,
  perr,
  pout,
  time_now,
  time_diff,
  Bitmask,
  ByteBuffer,
  TcpSocket,
)

import socket

import selectors

import signal
import atexit

import time
from datetime import datetime

import enum

from .config import (
  DEFAULT_CONFIG,
  Config,
)

from .request import (
  Request,
  RequestError,
)

## }}} ---- [ Imports ] ----------------------------------------------------------------------------

# Program name
PROG_NAME = os.path.basename(sys.argv[0])

# Configuration file
CONFIG_FILE = '/etc/fake-httpd.conf'

# List of handled signals
caught_signals = []

## {{{ exit_handler()
def exit_handler(arg):
  fake_httpd = arg

  log_files = [
    fake_httpd.main_log,
    fake_httpd.error_log,
    fake_httpd.debug_log,
    fake_httpd.access_log,
  ]

  fake_httpd.debug('closing log files')

  for log_file in log_files:
    if not log_file:
      continue

    log_file.flush()
    log_file.close()
## }}}

## {{{ signal_handler()
def signal_handler(sig, frame):
  caught_signals.append(signal.Signals(sig))
## }}}

## {{{ class LogLevel

class LogLevel(enum.Enum):

  INFO    = 1
  WARNING = 2
  ERROR   = 3
  DEBUG   = 4

## class LogLevel }}}

## {{{ class Counter

class Counter:

  value = None

  def __init__(self, value=0):
    self.value = value

  def inc(self):
    self.value += 1

  def dec(self):
    self.value -= 1

  def zero(self):
    self.value = 0

## class Counter }}}

## {{{ class Connection

class Connection:

  # Instance of TcpSocket
  socket = None

  # Remote address/port
  remote_addr = None
  remote_port = None

  # Read buffer
  buffer = None

  # Connection TTL
  expires = None
  expired = None

  ## {{{ Connection.__init__()
  def __init__(self, socket, remote_addr, remote_port, expires):
    self.socket = socket
    self.remote_addr = remote_addr
    self.remote_port = remote_port
    self.buffer = ByteBuffer()
    self.expires = time_now() + expires
    self.expired = False
  ## }}}

  ## {{{ Connection.__str__()
  def __str__(self):
    return f'<Connection {self.remote_addr}:{self.remote_port}>'
  ## }}}

  ## {{{ Connection.read()
  def read(self, size=4096):
    return self.socket.recv(size)
  ## }}}

## class Connection }}}

## {{{ class FakeHttpd

class FakeHttpd:

  config = None

  listener = None

  main_log = None
  error_log = None
  debug_log = None

  access_log = None

  io_selector = None
  iops_counter = None

  # Dict indexed by fd
  connections = {}

  ## {{{ FakeHttpd.main()
  def main(self, argv=sys.argv):
    self.info(f'pid {os.getpid()}, initialising...')

    # Load configuration
    self.init_config()

    # Create HOME with the correct permissions/ownership if it doesn't exist yet
    self.init_home()

    # Set restrictive umask as early as possible
    os.umask(0o077)

    # Initialise logging
    self.init_logging()

    # Create listener socket and bind to port 80
    self.create_listener()

    # Drop privileges if running as root
    self.drop_privileges()

    # Sanitise environment variables removing those we don't need
    self.sanitise_env()

    # chdir to $HOME
    try:
      os.chdir(os.environ['HOME'])
    except OSError as ex:
      self.die(f'chdir() failed: {ex}')

    # Register signal handlers
    self.register_signal_handlers()

    # Register exit handler
    atexit.register(exit_handler, self)

    # Enter main I/O loop
    self.debug('entering I/O loop')
    self.io_loop()

    # Never reached
    return 0
  ## }}}

  ## {{{ FakeHttpd.info()
  def info(self, message):
    pout(f'{PROG_NAME}: {message}')
    self.log(LogLevel.INFO, message)
  ## }}}

  ## {{{ FakeHttpd.warning()
  def warning(self, message):
    perr(f'{PROG_NAME}: warning: {message}')
    self.log(LogLevel.WARNING, message)
  ## }}}

  ## {{{ FakeHttpd.error()
  def error(self, message):
    perr(f'{PROG_NAME}: error: {message}')
    self.log(LogLevel.ERROR, message)
  ## }}}

  ## {{{ FakeHttpd.die()
  def die(self, message):
    self.error(message)
    exit(1)
  ## }}}

  ## {{{ FakeHttpd.debug()
  def debug(self, message):
    perr(f'{PROG_NAME}: debug: {caller(2)}(): {message}')
    self.log(LogLevel.DEBUG, message)
  ## }}}

  ## {{{ FakeHttpd.init_config()
  def init_config(self):
    self.config = Config()

    if os.path.isfile(CONFIG_FILE):
      self.config.from_file(CONFIG_FILE)
    else:
      self.config.from_dict(DEFAULT_CONFIG)

    for name, value in self.config.items():
      self.debug(f"{name} = {value}")
  ## }}}

  ## {{{ FakeHttpd.init_logging()
  def init_logging(self):
    log_dir = self.config['log_dir']
    for path in [log_dir]:
      try:
        os.mkdir(path, 0o700)
      except FileExistsError:
        pass
      except OSError as ex:
        self.die(f'mkdir() failed: {ex}')

    self.main_log = open(f'{log_dir}/main.log', 'a')
    self.error_log = open(f'{log_dir}/error.log', 'a')
    self.debug_log = open(f'{log_dir}/debug.log', 'a')
    self.access_log = open(f'{log_dir}/access.log', 'a')
  ## }}}

  ## {{{ FakeHttpd.init_home()
  def init_home(self):
    # FIXME: the below code is far from perfect and the bulk needs to be
    # abstracted away
    #

    # Set HOME to something accessible
    home_dir = self.config['home_dir']
    os.environ['HOME'] = home_dir

    if not os.path.isdir(home_dir):
      try:
        os.mkdir(home_dir, 0o750)
      except OSError as ex:
        self.die(f'mkdir() failed: {ex}')

    st = os.stat(home_dir)
    gid = grp.getgrnam(self.config['group']).gr_gid
    if st.st_gid != gid:
      try:
        os.chown(home_dir, 0, gid)
      except OSError as ex:
        self.die(f'chown() failed: {ex}')
  ## }}}

  ## {{{ FakeHttpd.log()
  def log(self, level, message):
    if level == LogLevel.INFO:
      log_file = self.main_log
    elif level == LogLevel.WARNING:
      log_file = self.main_log
    elif level == LogLevel.ERROR:
      log_file = self.error_log
    elif level == LogLevel.DEBUG:
      log_file = self.debug_log
    else:
      die(f"calling function {caller(2)}() called FakeHttpd.log() with invalid level argument")

    if not log_file:
      # Logging not initialised yet
      #
      # FIXME: it would be nice we kept a backlog which gets written out once
      # the respective log files have been opened
      return

    time_stamp = datetime.utcnow().strftime('%H:%M:%S %Y/%m/%d %s')
    log_file.write(f'{time_stamp} {message}\n')
    log_file.flush()
  ## }}}

  ## {{{ FakeHttpd.log_request()
  def log_request(self, request):
    # FIXME: eventually we'll use the Apache access log format, but for now this will do
    #
    message = f'{request.method} {request.uri} {request.version}'
    time_stamp = datetime.utcnow().strftime('%H:%M:%S %Y/%m/%d %s')
    self.access_log.write(f'{time_stamp} {message}\n')
    self.access_log.flush()
  ## }}}

  ## {{{ FakeHttpd.drop_privileges()
  def drop_privileges(self):
    if os.getuid() != 0:
      return

    self.debug("running as root, dropping privileges")

    new_uid = None
    try:
      new_uid = pwd.getpwnam(self.config['user']).pw_uid
    except KeyError as ex:
      self.die(f"user {self.config['user']} not found in /etc/passwd")

    new_gid = None
    try:
      new_gid = grp.getgrnam(self.config['group']).gr_gid
    except KeyError as ex:
      self.die(f"group {self.config['group']} not found in /etc/group")

    # Clear supplementary groups
    try:
      os.setgroups([])
    except OSError as ex:
      self.die(f'setgroups() failed: {ex}')

    # Switch GID
    try:
      os.setgid(new_gid)
    except OSError as ex:
      self.die(f'setgid() failed: {ex}')

    # Switch UID
    try:
      os.setuid(new_uid)
    except OSError as ex:
      self.die(f'setuid() failed: {ex}')

    self.debug('root privileges dropped')
    self.debug(f'new resuid = {os.getresuid()}')
    self.debug(f'new resgid = {os.getresgid()}')
  ## }}}

  ## {{{ FakeHttpd.create_listener()
  def create_listener(self):
    self.listener = TcpSocket()

    try:
      self.debug('binding to 0.0.0.0:80')
      self.listener.bind('0.0.0.0', 80, reuse_addr=True)
    except socket.error as ex:
      self.die(f'bind() failed: {ex}')

    try:
      self.listener.listen()
    except socket.error as ex:
      self.die(f'listen() failed: {ex}')

    # Make underlying socket non-blocking
    self.listener.blocking(False)
  ## }}}

  ## {{{ FakeHttpd.sanitise_env()
  def sanitise_env(self):
    # Keep only the bare minimum
    keep = ['HOME', 'LANG', 'PATH']

    delete = []
    for name in os.environ:
      if name not in keep:
        delete.append(name)

    for name in delete:
      del os.environ[name]

    # Remove any inaccessible directories from PATH
    #

    new_path = []
    for path in os.environ['PATH'].split(':'):
      if not os.access(path, os.R_OK):
        self.debug(f'removing {path} from PATH')
        continue
      new_path.append(path)

    new_path = ':'.join(new_path)

    os.environ['PATH'] = new_path
    self.debug(f"set PATH to '{new_path}'")
  ## }}}

  ## {{{ FakeHttpd.register_signal_handlers()
  def register_signal_handlers(self):
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGALRM, signal_handler)
  ## }}}

  ## {{{ FakeHttpd.handle_sigint()
  def handle_sigint(self):
    perr('')
    self.debug('caught SIGINT, exiting')
    exit(0)
  ## }}}

  ## {{{ FakeHttpd.handle_sighup()
  def handle_sighup(self):
    self.debug('caught SIGHUP, exiting')
    exit(0)
  ## }}}

  ## {{{ FakeHttpd.handle_sigterm()
  def handle_sigterm(self):
    self.debug('caught SIGTERM, exiting')
    exit(0)
  ## }}}

  ## {{{ FakeHttpd.io_loop()
  def io_loop(self):
    self.io_selector = selectors.DefaultSelector()
    self.io_selector.register(self.listener._socket, selectors.EVENT_READ)

    self.iops_counter = Counter()

    while True:
      self.io_loop_once()
  ## }}}

  ## {{{ FakeHttpd.io_loop_once()
  def io_loop_once(self):
    while len(caught_signals) > 0:
      sig = caught_signals.pop(0)
      if sig == signal.SIGINT:
        self.handle_sigint()
      elif sig == signal.SIGHUP:
        self.handle_sighup()
      elif sig == signal.SIGTERM:
        self.handle_sigterm()
      else:
        die(f'caught unexpected signal {sig.name}')

    self.iops_counter.zero()

    events = self.io_selector.select(timeout=0)
    for key, mask in events:
      sock = key.fileobj
      if sock == self.listener._socket:
        sock, remote = self.accept_connection()
        if not sock:
          continue
        self.debug(f'accepted connection from {remote[0]}:{remote[1]}')
        self.add_connection(TcpSocket(sock), remote)
        self.iops_counter.inc()
      else:
        conn = self.connections[sock.fileno()]
        self.process(conn)

    delete = []

    for fd, conn in self.connections.items():
      now = time_now()
      diff = time_diff(conn.expires, now)
      if diff <= 0:
        self.debug(f'connection {conn} has expired')
        self.remove_connection(conn)
        delete.append(fd)

    for fd in delete:
      conn = self.connections[fd]
      message = f'removed {conn}'

      del self.connections[fd]
      del conn

      self.debug(message)

    if self.iops_counter.value > 0:
      self.debug(f'performed {self.iops_counter.value} I/O operation(s)')
    else:
      # We're idle, take a nap
      time.sleep(0.25)

  ## }}}

  ## {{{ FakeHttpd.accept_connection()
  def accept_connection(self):
    try:
      return self.listener.accept()
    except BlockingIOError:
      pass
    except OSError as ex:
      die(f'accept() failed: {ex}')
  ## }}}

  ## {{{ FakeHttpd.add_connection()
  def add_connection(self, socket, remote):
    fd = socket._fd
    self.connections[fd] = Connection(socket, remote[0], remote[1], int(self.config['timeout']))
    self.io_selector.register(socket._socket, selectors.EVENT_READ)
    self.debug(f'added {self.connections[fd]}')
  ## }}}

  ## {{{ FakeHttpd.remove_connection()
  def remove_connection(self, conn):
    fd, sock = conn.socket._fd, conn.socket

    self.debug(f'removing fd {fd} from I/O selector')
    self.io_selector.unregister(sock._socket)

    self.debug(f'marking connection {self.connections[fd]} as removed')

    sock.shutdown()
    sock.close()
  ## }}}

  ## {{{ FakeHttpd.process()
  def process(self, conn):
    try:
      buf = conn.read()
      if not buf:
        return
    except OSError as ex:
      self.debug(f'{conn}: {ex}')

    self.iops_counter.inc()
    conn.buffer.append(buf)

    try:
      num_lines = conn.buffer.to_str().count('\r\n')
    except UnicodeDecodeError:
      # FIXME: this needs better handling
      return

    self.debug(f'read {len(buf)} bytes and {num_lines} lines from {conn.remote_addr}')

    if num_lines < 1:
      return

    complete = conn.buffer.to_str().endswith('\r\n')
    if not complete:
      return

    self.debug(f'read correctly-terminated request from {conn}')
    self.process_request(conn)
  ## }}}

  ## {{{ FakeHttpd.process_request()
  def process_request(self, conn):
    self.debug(f'processing request from {conn}')

    complete = conn.buffer.to_str().endswith('\r\n')
    if not complete:
      self.debug('called with incomplete request, returning')
      return

    request = Request()

    try:
      request.parse(conn.buffer.value())
      self.log_request(request)
    except RequestError as ex:
      self.debug(f'received invalid request: {ex}')

    # We won't be reading from this socket again, so shutdown() the read side
    conn.socket.shutdown(socket.SHUT_RD)

    # NOTE: we let the expiry code handle disconnections instead of doing so
    # here.  This is a fake httpd after all, so leaving the abusive users we're
    # aiming to to discover hanging will hopefully result in much less traffic
    # from said users reaching us before they're added to the firewall's reject
    # list.

  ## }}}

## class FakeHttpd }}}

## {{{ main()
def main(argv=sys.argv):
  fake_httpd = FakeHttpd()
  status = fake_httpd.main()
  exit(status)
## }}}

##
# vim: ts=2 sw=2 tw=100 et fdm=marker :
##
