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

import socket

import selectors

import signal
import atexit

import time
from datetime import datetime

import json

import lzma

import enum

## }}} ---- [ Imports ] ----------------------------------------------------------------------------

# Program name
PROG_NAME = os.path.basename(sys.argv[0])

# HOME directory
HOME_DIR = '/var/lib/fake-httpd'

# Directory where we store compressed JSON-encoded Request objects
REQUESTS_DIR = f'{HOME_DIR}/requests'

# Top-level log directory
LOG_DIR = '/var/log/fake-httpd'

# Time in seconds to expire idle connections
CONNECTION_TIMEOUT = 30

# List of handled signals
caught_signals = []

## {{{ func_name()
def func_name(frame=1):
  return sys._getframe(frame).f_code.co_name
## }}}

## {{{ perr()
def perr(s, end='\n', flush=True):
  print(s, file=sys.stderr, end=end, flush=flush)
## }}}

## {{{ pout()
def pout(s, end='\n', flush=True):
  print(s, file=sys.stdout, end=end, flush=flush)
## }}}

## {{{ index()
def index(s, needle):
  try:
    return s.index(needle)
  except ValueError:
    return -1
## }}}

## {{{ time_now()
def time_now():
  return int(time.time())
## }}}

## {{{ time_diff()
def time_diff(t1, t2):
  return t1 - t2
## }}}

## {{{ random_uuid()
def random_uuid():
  with open('/proc/sys/kernel/random/uuid') as fp:
    return fp.read().split('\n')[0]
## }}}

## {{{ exit_handler()
def exit_handler(arg):
  fake_httpd = arg

  log_files = [
    fake-httpd.main_log,
    fake-httpd.error_log,
    fake-httpd.debug_log,
    fake-httpd.access_log,
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

## {{{ class TcpSocket

class TcpSocket:

  # Instance of socket
  _socket = None

  # Underlying file descriptor
  _fd = None

  ## {{{ TcpSocket.__init__()
  def __init__(self, sock=None):
    if sock is None:
      self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
      self._socket = sock

    self._fd = self._socket.fileno()
  ## }}}

  ## {{{ TcpSocket.setblocking()
  def setblocking(self, block=True):
    self._socket.setblocking(block)
  ## }}}

  ## {{{ TcpSocket.bind()
  def bind(self, address, port, reuse_addr=False):
    if reuse_addr:
      self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    self._socket.bind((address, port))
  ## }}}

  ## {{{ TcpSocket.listen()
  def listen(self, backlog=10):
    self._socket.listen(backlog)
  ## }}}

  ## {{{ TcpSocket.accept()
  def accept(self):
    return self._socket.accept()
  ## }}}

  ## {{{ TcpSocket.recv()
  def recv(self, size, flags=0):
    if flags != 0:
      return self._socket.recv(size)
    else:
      return self._socket.recv(size, flags)
  ## }}}

  ## {{{ TcpSocket.shutdown()
  def shutdown(self, how=socket.SHUT_RDWR):
    self._socket.shutdown(how)
  ## }}}

  ## {{{ TcpSocket.close()
  def close(self):
    self._socket.close()
  ## }}}

## class TcpSocket }}}

## {{{ class Bitmask

class Bitmask:

  _mask = None

  def __init__(self):
    self.reset()

  def reset(self):
    self._mask = 0

  def set(self, bit):
    self._mask |= bit

  def clear(self, bit):
    self._mask &= ~bit

  def test(self, bit):
    return self._mask & bit

## class Bitmask }}}

## {{{ class Buffer

class Buffer:

  _buf = None

  def __init__(self):
    self._buf = []

  def append(self, buf):
    self._buf.append(buf)

  def size(self):
    size = 0
    for buf in self._buf:
      size += len(buf)
    return size

  def get_bytes(self):
    return b''.join(self._buf)

  def get_str(self):
    return self.get_bytes().decode('utf-8')

## class Buffer }}}

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
  def __init__(self, socket, remote_addr, remote_port):
    self.socket = socket
    self.remote_addr = remote_addr
    self.remote_port = remote_port
    self.buffer = Buffer()
    self.expires = time_now() + CONNECTION_TIMEOUT
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

## class TcpSocket }}}

## {{{ class Request

class Request:

  uuid = None
  remote_addr = None
  timestamp = None
  raw = None
  invalid = None
  method = None
  uri = None
  version = None
  headers = None

  ## {{{ Request.__init__()
  def __init__(self, uuid, remote_addr):
    self.uuid = uuid
    self.timestamp = int(datetime.utcnow().timestamp())
    self.remote_addr = remote_addr
    self.invalid = False
  ## }}}

  ## {{{ Request.to_dict()
  def to_dict(self):
    dict = {
      'uuid': self.uuid,
      'remote_addr': self.remote_addr,
      'invalid': self.invalid,
    }

    for attr in ['timestamp', 'raw', 'method', 'uri', 'version', 'headers']:
      value = getattr(self, attr)
      if value:
        dict[attr] = value

    return dict
  ## }}}

  ## {{{ Request.parse()
  def parse(self, buf):
    self.raw = buf

    request, headers = self.raw.split('\r\n', 1)
    if request.count(' ') != 2:
      self.invalid = True
      return

    method, uri, version = request.split(' ')
    self.method = method
    self.uri = uri
    self.version = version

    valid_methods = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE', 'CONNECT']
    if method not in valid_methods:
      self.invalid = True
      return

    if headers.endswith('\r\n\r\n'):
      headers = headers[:-4]
    else:
      perr('DEBUG: Request.parse() called incomplete request!')
      self.invalid = True
      return

    self.headers = {}
    for header in headers.split('\r\n'):
      if not header:
        continue

      if header.count(': ') < 1:
        self.invalid = True
        return

      name, value = header.split(': ', 1)
      self.headers[name] = value
  ## }}}

## class Request }}}

## {{{ class FakeHttpd

class FakeHttpd:

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
    # Create HOME with the correct permissions/ownership if it doesn't exist yet
    self.init_home()

    # Set restrictive umask as early as possible
    os.umask(0o077)

    # Initialise logging
    self.init_logging()

    self.info(f'pid {os.getpid()}, initialising...')

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
    perr(f'{PROG_NAME}: debug: {func_name(2)}(): {message}')
    self.log(LogLevel.DEBUG, message)
  ## }}}

  ## {{{ FakeHttpd.init_logging()
  def init_logging(self):
    for path in [LOG_DIR]:
      try:
        os.mkdir(path, 0o700)
      except FileExistsError:
        pass
      except OSError as ex:
        self.die(f'mkdir() failed: {ex}')

    self.main_log = open(f'{LOG_DIR}/main.log', 'a')
    self.error_log = open(f'{LOG_DIR}/error.log', 'a')
    self.debug_log = open(f'{LOG_DIR}/debug.log', 'a')
    self.access_log = open(f'{LOG_DIR}/access.log', 'a')
  ## }}}

  ## {{{ FakeHttpd.init_home()
  def init_home(self):
    # FIXME: the below code is far from perfect and the bulk needs to be
    # abstracted away
    #

    # Set HOME to something accessible
    os.environ['HOME'] = HOME_DIR

    if not os.path.isdir(HOME_DIR):
      try:
        os.mkdir(HOME_DIR, 0o750)
      except OSError as ex:
        self.die(f'mkdir() failed: {ex}')

    st = os.stat(HOME_DIR)
    gid = grp.getgrnam('nogroup').gr_gid
    if st.st_gid != gid:
      try:
        # chwon root:nobody /var/lib/fake-httpd
        os.chown(HOME_DIR, 0, gid)
      except OSError as ex:
        self.die(f'chown() failed: {ex}')

    requests_dir = REQUESTS_DIR
    if not os.path.isdir(requests_dir):
      try:
        os.mkdir(requests_dir, 0o700)
      except OSError as ex:
        self.die(f'mkdir() failed: {ex}')

    st = os.stat(requests_dir)
    uid = pwd.getpwnam('nobody').pw_uid
    if st.st_uid != uid:
      try:
        # chwon nobody:root /var/lib/fake-httpd/requests
        os.chown(requests_dir, uid, 0)
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
      die(f"calling function {func_name(2)}() called FakeHttpd.log() with invalid level argument")

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
    message = request.raw.split('\r\n', 1)[0]
    time_stamp = datetime.utcnow().strftime('%H:%M:%S %Y/%m/%d %s')
    self.access_log.write(f'{time_stamp} {message}\n')
    self.access_log.flush()

    request_log_file = f'{REQUESTS_DIR}/{request.uuid}'
    with open(request_log_file, 'wb') as fp:
      jb = bytes(json.dumps(request.to_dict()), 'utf-8')
      fp.write(lzma.compress(jb))
  ## }}}

  ## {{{ FakeHttpd.drop_privileges()
  def drop_privileges(self):
    if os.getuid() != 0:
      return

    self.debug("running as root, dropping privileges")

    new_uid = None
    try:
      new_uid = pwd.getpwnam('nobody').pw_uid
    except KeyError as ex:
      self.die(f'user nobody not found in /etc/passwd')

    new_gid = None
    try:
      new_gid = grp.getgrnam('nogroup').gr_gid
    except KeyError as ex:
      self.die(f'group nogroup not found in /etc/group')

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
    self.listener.setblocking(False)
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
      if diff < 1:
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
    self.connections[fd] = Connection(socket, remote[0], remote[1])
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
      num_lines = conn.buffer.get_str().count('\r\n')
    except UnicodeDecodeError:
      # FIXME: this needs better handling
      return

    self.debug(f'read {len(buf)} bytes and {num_lines} lines from {conn.remote_addr}')

    if num_lines < 1:
      return

    complete = conn.buffer.get_str().endswith('\r\n')
    if not complete:
      return

    self.debug(f'read correctly-terminated request from {conn}')
    self.process_request(conn)
  ## }}}

  ## {{{ FakeHttpd.process_request()
  def process_request(self, conn):
    self.debug(f'processing request from {conn}')

    complete = conn.buffer.get_str().endswith('\r\n')
    if not complete:
      self.debug('called with incomplete request, returning')
      return

    uuid = None
    while True:
      uuid = random_uuid()
      if self.uuid_is_unique(uuid):
        break

    request = Request(uuid, conn.remote_addr)
    request.parse(conn.buffer.get_str())

    self.log_request(request)

    if request.invalid:
      self.debug(f'invalid request from {conn}')

    # We won't be reading from this socket again, so shutdown() the read side
    conn.socket.shutdown(socket.SHUT_RD)

    # NOTE: we let the expiry code handle disconnections instead of doing so
    # here.  This is a fake httpd after all, so leaving the abusive users we're
    # aiming to to discover hanging will hopefully result in much less traffic
    # from said users reaching us before they're added to the firewall's reject
    # list.

  ## }}}

  ## {{{ FakeHttpd.uuid_is_unique()
  def uuid_is_unique(self, uuid):
    # FIXME: this is perhaps too paranoid, but let's be 100% certain that the
    # request UUID we're about to use is positively unique

    request_log_file = f'{REQUESTS_DIR}/{uuid}'
    if os.path.isfile(request_log_file):
      self.debug(f'{request_log_file}: file exists')
      return False

    return True
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
