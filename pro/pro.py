#!/usr/bin/env python

import os
import sys
import re
import string
import socket
import select
import time
import signal
import errno
import logging
import warnings
import locale
import urlparse
import urllib
import httplib
import cgi
import ssl
import hashlib
import random
import tempfile
import glob
import subprocess
import traceback

from datetime import datetime, timedelta
from collections import OrderedDict
from httplib import InvalidURL, CannotSendRequest, ImproperConnectionState
from httplib import BAD_REQUEST, BAD_GATEWAY, REQUEST_TIMEOUT, GATEWAY_TIMEOUT

RX, TX = 0, 1
HTTP_VERSION = 'HTTP/1.1'
PRO_VERSION = 'ProAgent/1.0'
PRO_SELECTOR = '/_PRO_/'
PRO_METHOD = 'POST'
REFRESH_SELECTOR = 'http://localhost/_PRO_/REFRESH/'
PING_SELECTOR = 'http://localhost/_PRO_/PING/'
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
WS_VERSION = 13
CHAR_62 = 'J3rdbwaV84AoIDqjv7KuxLOesz1Ulg02nWmHpSFZMcGkTPRB9Qh6NtX5CiyfYE'
RAHC_62 = '9lT2gzuPOeRs1jm8BQAdL0G5K3SHWv7xJiUqoVCakMIpZYEr6cwytF4bDnfhXN'
MARKER_STOP = '.\r\n'
MARKER_BEAT = ',\r\n'
MARKER_OKAY = '+\r\n'
MARKER_LEN = 3
NO_CACHE = 'Cache-Control: no-cache\r\nPragma: no-cache\r\nExpires: -1\r\n'
TRAN_C2R = string.maketrans(CHAR_62 + '+._/', RAHC_62 + '.+/_')
TRAN_R2C = string.maketrans(RAHC_62 + '.+/_', CHAR_62 + '+._/')
EXPECT = '%s 101' % HTTP_VERSION
FAIL_IF = [r'\r\nServer: Cowboy\r\n']
LOCALHOST_REGEX = re.compile(r'localhost(\.localdomain)?\.?$|'
                             r'127\.0\.0\.\d+$', re.I)
UPSTREAM_PORTMAP = {'http': 8080, 'https': 8443,
                    'pro+http': 80, 'pro+https': 443}
REFRESH_SLEEP = 9
AUTH_SLEEP = 4

PORT = int(os.environ.get('PORT', 8080))
SERVER = bool(int(os.environ.get('SERVER', 0)))
LOCAL_OK = bool(int(os.environ.get('LOCAL_OK', 0)))
CREDS = os.environ.get('CREDS', '')
OUR_IP = os.environ.get('OUR_IP', '')

QUIET = bool(int(os.environ.get('QUIET', 0)))
DEBUG = bool(int(os.environ.get('DEBUG', 0)))
IOTRACE = bool(int(os.environ.get('IOTRACE', 0)))
DEBUG_LOG = os.environ.get('DEBUG_LOG', '')
DUMP_LEN = int(os.environ.get('DUMP_LEN', 256))

APP_NAME = os.environ.get('APP_NAME', '')
APP_TOKEN = os.environ.get('APP_TOKEN', '')
APP_DYNO = os.environ.get('APP_DYNO', 'web.1')

UPSTREAM = os.environ.get('UPSTREAM', None)
UPSTREAM_POLICY = os.environ.get('UPSTREAM_POLICY', 'error,ordered')
SALT = os.environ.get('SALT', PRO_SELECTOR)
FORCE_PRIVATE = bool(int(os.environ.get('FORCE_PRIVATE', 0)))
TOLERATE_SEC = int(os.environ.get('TOLERATE_SEC', 120))
KEEPALIVE_SEC = float(os.environ.get('KEEPALIVE_SEC', 120))
REFRESH_ON_COUNT = int(os.environ.get('REFRESH_ON_COUNT', 0))

BUFLEN = int(os.environ.get('BUFLEN', 8192))
POLL_SEC = float(os.environ.get('POLL_SEC', 5.0))
TIMEOUT = float(os.environ.get('TIMEOUT', 60))
SOCK_SHUTDOWN_MODE = os.environ.get('SOCK_SHUTDOWN_MODE', '+')
SHUTDOWN_SLEEP_SEC = float(os.environ.get('SHUTDOWN_SLEEP_SEC', 0.1))
QUIRK_CONN_RESET = int(os.environ.get('QUIRK_CONN_RESET', 0))
GEVENT = bool(int(os.environ.get('GEVENT', 0)))

ACCEPT_HEADERS = set(['sec-websocket-key', 'connection',
                      'proxy-connection', 'proxy-authorization'])

SLOW_HELLO = bool(int(os.environ.get('SLOW_HELLO', 0)))
SLOW_SLEEP = int(os.environ.get('SLOW_SLEEP', 1))
SLOW_TOTAL = int(os.environ.get('SLOW_TOTAL', 10))
SLOW_STEP = int(os.environ.get('SLOW_STEP', 5))

ECHO_PROBE_TIMEOUT = 0.5
ECHO_MEM_LIMIT = int(os.environ.get('ECHO_MEM_LIMIT', 10 * 1024 * 1024))
ECHO_TEST_PATTERN = 'abcdefghijklmnopqrstuvwxyz'
ECHO_HIDE_SERVER_HEADERS = set([
    'x-request-id', 'x-request-start', 'connect-time', 'total-route-time'])

if GEVENT:
    import gevent
    from gevent import Greenlet
    from gevent.event import Event
    from gevent.queue import JoinableQueue as Queue_
    from gevent.queue import Empty
    try:
        from gevent.select import poll as poll_impl
    except ImportError:
        poll_impl = None
    from gevent import monkey
    monkey.patch_all()
else:
    import threading
    from threading import Thread, Event
    from Queue import Queue as Queue_
    from Queue import Empty
    from select import poll as poll_impl

logger = logging.getLogger('pro')
logging.captureWarnings(True)

if os.environ.get('COVERAGE_PROCESS_START', None):
    import coverage
    coverage.process_startup()

PROFILER = os.environ.get('PROFILER', '').strip()
if PROFILER == '-line_profiler':
    _line_profiler = profile
else:
    def _line_profiler(func):
        return func

ENABLE_NUMPY = bool(int(os.environ.get('ENABLE_NUMPY', 1)))
if ENABLE_NUMPY:
    try:
        import numpy
    except ImportError:
        warnings.warn('numpy not found')
        ENABLE_NUMPY = None

TEST = os.environ.get('TEST', '')
if TEST:
    FIXME_CA_PER_TEST = False
    FIXME_HIDE_EOF = False
    FIXME_HIDE_SSL_WARNINGS = True

    import requests
    from requests.exceptions import ConnectionError, SSLError
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from requests.packages.urllib3.exceptions import SubjectAltNameWarning

    if FIXME_HIDE_SSL_WARNINGS:
        warnings.simplefilter('once', InsecureRequestWarning)
        warnings.simplefilter('ignore', SubjectAltNameWarning)
        logging.getLogger('requests.packages.urllib3').setLevel(logging.WARN)

SSL_CERT = os.environ.get('SSL_CERT', '')
SSL_CACERTS = os.environ.get('SSL_CACERTS', '')
if TEST or (SSL_CERT and SSL_CERT.startswith('+')):
    CA_PATH_FMT = os.environ.get('CA_PATH_FMT', '.dummy_ca_%s.pem')
    try:
        import OpenSSL
        from OpenSSL import crypto
        from OpenSSL.SSL import FILETYPE_PEM
    except ImportError:
        warnings.warn('openssl not found')
        OpenSSL = None
else:
    OpenSSL = False

try:
    import certifi
except ImportError:
    certifi = None


def system_cacerts():
    if SSL_CACERTS and os.path.exists(SSL_CACERTS):
        return SSL_CACERTS
    if certifi is not None:
        return certifi.where()
    cacerts_cache = os.path.join(tempfile.gettempdir(), '.echo_pro.cacerts')
    if os.path.exists(cacerts_cache):
        return cacerts_cache
    with open(cacerts_cache, 'w') as f:
        for cacert in glob.glob('/etc/ssl/certs/*.pem'):
            f.write(open(cacert).read())
    return cacerts_cache


def eintr_retry(func, *args):
    while 1:
        try:
            return func(*args)
        except (OSError, select.error) as err:
            if err.args[0] != errno.EINTR:
                raise


def safe_sleep(sleep_sec):
    if sleep_sec > 0:
        end_time = time.time() + sleep_sec
        while 1:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            time.sleep(remaining)


if GEVENT:
    class NextThreadName(object):
        def __init__(self):
            self.num = 0

        def __call__(self):
            self.num += 1
            return 'Thread-%d' % self.num

    _next_thread_name = NextThreadName()
    gevent.getcurrent().name = 'Thread-Main'

    def current_thread_name():
        return gevent.getcurrent().name

    def spawn_thread(daemon, func, *args):
        thread = Greenlet(func, *args)
        thread.name = _next_thread_name()
        thread.start()
        return thread

    def thread_is_alive(thread):
        return thread is not None and not thread.ready()

if not GEVENT:
    def current_thread_name():
        return threading.current_thread().name

    def spawn_thread(daemon, func, *args):
        thread = Thread(target=func, args=args)
        thread.daemon = True
        thread.start()
        return thread

    def thread_is_alive(thread):
        return thread is not None and thread.is_alive()


def dump(data, max=DUMP_LEN, short=False):
    if not data:
        dump = str(data.tobytes() if isinstance(data, memoryview) else data)
        return dump if dump else '"%s"' % dump
    big = max is not None and max != -1 and len(data) > max
    if big:
        dump1, dump2 = data[:max/2], data[-max/2:]
    if isinstance(data, memoryview):
        if big:
            dump1, dump2 = dump1.tobytes(), dump2.tobytes()
        else:
            dump = data.tobytes()
    elif isinstance(data, (bytes, bytearray)):
        if big:
            dump1, dump2 = bytes(dump1), bytes(dump2)
        else:
            dump = bytes(data)
    else:  # unicode string
        if big:
            dump1 = dump1.encode('utf-8', 'replace')
            dump2 = dump2.encode('utf-8', 'replace')
        else:
            dump = data.encode('utf-8', 'replace')
    if big:
        dump1 = dump1.encode('string-escape')[:max/2]
        dump2 = dump2.encode('string-escape')[-max/2:]
        if short:
            return '"%s"..."%s"' % (dump1, dump2)
        return '(%d)""%s"..."%s""' % (len(data), dump1, dump2)
    length_mark = '' if len(data) < 10 or short else '(%d)' % len(data)
    return '%s"%s"' % (length_mark, dump.encode('string-escape'))


def decode_userpass(username=None, password=None):
    def _decode_once(username, password):
        if password and not username:
            username, password = password, None
        if username and not password:
            username, _, password = username.partition(':')
        return decode_token(username), decode_token(password)
    return _decode_once(*_decode_once(username, password))


def decode_token(token):
    if token is None:
        token = ''
    if token.startswith(('/b/', '$b$', '~b~', '[b]')):
        return (token[3:] + '==').decode('base64')
    if token.startswith(('b$', 'b~')):
        return (token[2:] + '==').decode('base64')
    return token


def parse_upstream_line(upstream_line):
    upstream_list = []
    if not upstream_line:
        return upstream_list
    for upstream_uri in upstream_line.split(','):
        upstream_uri = upstream_uri.strip()
        if '://' not in upstream_uri:
            upstream_uri = 'pro://' + upstream_uri
        uri = urlparse.urlparse(upstream_uri)
        scheme = ('pro+http' if uri.scheme == 'pro' else
                  'pro+https' if uri.scheme == 'pros' else uri.scheme)
        default_port = UPSTREAM_PORTMAP.get(scheme, 0)
        if not default_port:
            raise ValueError('Invalid upstream string %s', upstream_uri)

        ipaddr = socket.gethostbyname(uri.hostname)
        port = int(uri.port or default_port)
        userpass = '%s:%s' % decode_userpass(uri.username, uri.password)

        upstream = {
            'hostaddr': '%s:%d' % (uri.hostname, port),
            'ipaddr': '%s:%d' % (ipaddr, port),
            'userpass': None if userpass == ':' else userpass,
            'type': scheme,
            'private': '/private/' in uri.path,
            'lowbuf': '/lowbuf/' in uri.path,
            }
        upstream_list.append(upstream)
    return upstream_list


def parse_upstream_policy(policy_line):
    error = sequence = None
    for token in [s.strip() for s in (policy_line or '').split(',')]:
        if not token:
            continue
        elif token == 'error' and error is None:
            error = True
        elif token == 'always' and error is None:
            error = False
        elif token in ('random', 'ordered') and sequence is None:
            sequence = token
        else:
            raise AssertionError('Invalid upstream policy: %s' % policy_line)
    if error is None:
        error = True
    if sequence is None:
        sequence = 'ordered'
    return {'error': error, 'sequence': sequence}


def _make_signature(parts, secret=None, rand_3char=None, delta_sec=0,
                    tolerate_sec=TOLERATE_SEC, time_utc=None):
    if time_utc is None:
        time_utc = datetime.utcnow()
    time_utc = time_utc.replace(microsecond=0)
    delta = (time_utc.minute * 60 + time_utc.second + delta_sec) % tolerate_sec
    time_str = (time_utc + timedelta(seconds=delta_sec - delta)).isoformat()
    if rand_3char is None:
        rand_3char = (CHAR_62[time_utc.microsecond % 60] +
                      CHAR_62[time_utc.second] + random.choice(CHAR_62))
    line = ' '.join([SALT, secret or ':', time_str, rand_3char] + parts)
    sign = hashlib.sha1(line).digest().encode('base64').rstrip('=\n')
    if IOTRACE:
        logger.debug('raw signature: %s', dump(line))
    return sign + rand_3char


def sign_request(req, secret=None, delta_sec=0, time_utc=None):
    parts = req if isinstance(req, (list, tuple)) else req.split()
    sign = _make_signature(parts, secret,
                           delta_sec=delta_sec, time_utc=time_utc)
    return ' '.join(parts + [sign])


def verify_request(req, secret=None, tolerate_sec=TOLERATE_SEC, time_utc=None):
    if req:
        parts = req if isinstance(req, (list, tuple)) else req.split()
        if len(parts) > 1:
            parts, sign = parts[:-1], parts[-1]
            if len(sign) > 3:
                rand_3char = sign[-3:]
                if time_utc is None:
                    time_utc = datetime.utcnow()
                for delta_sec in (0, -tolerate_sec, +tolerate_sec):
                    check = _make_signature(parts, secret, rand_3char,
                                            delta_sec, tolerate_sec, time_utc)
                    if sign == check:
                        return True
    return False


def do_refresh():
    if not SERVER:
        raise NotImplementedError
    headers = {
        'Accept': 'uooWnMuFnsJ_BJ2+w5Tspd.8KsJ; B5TKnsJ=l'.translate(TRAN_R2C),
        'Content-Type': 'application/json',
        'Authorization': 'Bearer %s' % decode_token(APP_TOKEN)
    }
    url = '{base}/{app}/dynos/{dyno}'.format(
        base='wFFoK:__uon+w5Tspd+MsU_uooK'.translate(TRAN_R2C),
        app=APP_NAME, dyno=APP_DYNO)
    logger.info('refreshing...')
    parts = urlparse.urlparse(url)
    conn = httplib.HTTPSConnection(parts.hostname)
    conn.request('DELETE', parts.path, headers=headers)
    conn.getresponse()
    time.sleep(REFRESH_SLEEP)


def format_date():
    return (datetime.utcnow().strftime('%A, %d %b %Y %H:%M:%S GMT')
            .encode('utf8', 'replace'))


class ProHandler(object):

    CMETHOD = 'DGttNDZ'.translate(TRAN_R2C)

    def __init__(self, server):
        self.server = server
        self.debug = server.debug
        self.idle_max = int(self.server.timeout / POLL_SEC)
        self.total_len = BUFLEN * 2 + 20
        self.socks = [None, None]
        self.bufs = [bytearray(self.total_len), bytearray(self.total_len)]
        self.mems = [memoryview(buf) for buf in self.bufs]

        self.next_request = None
        self.request_count = 0
        self.io_count = 0
        self.accepting = False
        self.event_sock = socket.socketpair()

    def cleanup(self):
        self.accepting = False
        self.bufs = self.code_arr = None
        self.close()
        for sock in self.event_sock:
            sock.close()

    def accept_next_request(self, request):
        if self.accepting:
            self.next_request = request
            self.event_sock[1].sendall('.')
            self.accepting = False
            return True

    def run(self, first_request):
        logger.debug('-------- thread starting --------')

        self.next_request = first_request
        status = 'aborted'

        self.spec = [0, 0]
        self.rx_bytes = [0, 0]
        self.tx_bytes = [0, 0]
        self.code_seq = [None, None]
        self.code_arr = [None, None]
        self.code_pos = [[-1, -1], [-1, -1]]

        try:
            while self.next_request and self.next_request != '<stop>':
                self.socks[RX], self.client_address = self.next_request
                self.next_request = None
                self.request_incr()
                logger.debug(
                    '---- request #%(count)d from %(addr)s ----',
                    dict(count=self.request_count, addr=self.client_address))
                self.handle_request_unsafe()
            status = 'complete'
        except ssl.SSLError as err:
            logger.info('ssl error: %s', err)
        except socket.error as err:
            code = BAD_GATEWAY if self.last_io == TX else REQUEST_TIMEOUT
            if (err.errno == -2 and self.method == self.CMETHOD and
                    self.tx_bytes[RX] and self.tx_bytes[TX] and
                    not self.spec[TX]):
                status = 'terminated'
            else:
                self.send_error(code, err)
            logger.debug('%(code)d %(error)s [%(io)d]',
                         dict(code=code, error=err, io=self.last_io))
        except InvalidURL as err:
            self.send_error(BAD_REQUEST, err)
            logger.debug('bad request: %s' % err)
        except CannotSendRequest as err:
            logger.debug(err)
        except ImproperConnectionState as err:
            logger.info(err)
        except SystemExit:
            logger.debug('thread canceled')
        except Exception:
            logger.warning(traceback.format_exc())
        finally:
            logger.debug('-------- thread %s --------', status)
            self.cleanup()

    def request_incr(self):
        self.request_count += 1
        self.server.global_request_count += 1

    def handle_request_unsafe(self):
        self.ends = [0, 0]
        self.s_beg = [0, 0]
        self.s_end = [0, 0]
        self.headers = {}
        self.last_io = -1
        self.method = ''
        self.version = HTTP_VERSION
        self.authorized = False
        self.last_heartbeat = time.time()

        self.trusted_ip = False
        dotted = self.client_address[0] + '.'
        for ip in self.server.our_ip:
            if dotted.startswith(ip):
                self.trusted_ip = True
                break

        self.socks[RX].settimeout(self.server.timeout)
        if self.server.ssl_cert:
            self.socks[RX] = ssl.wrap_socket(self.socks[RX], server_side=True,
                                             certfile=self.server.ssl_cert)

        split = self.parse_request()

        if SERVER:
            if not (self.method == self.CMETHOD or
                    self.selector.startswith(('http://', 'https://')) or
                    (self.method == PRO_METHOD and
                     self.selector.startswith(PRO_SELECTOR))):
                return self.simple_response(split)

        tail, _hdrend = self.parse_headers(split)
        upline = self.get_upline()

        if self.server.upstreams:
            self.send_upstream(upline, tail)
        elif self.method == self.CMETHOD:
            self.make_connect(tail)
        elif SERVER or upline:
            self.handle_upstream(upline, tail)
        else:
            self.make_request(tail)

    def get_upline(self):
        if (self.method != PRO_METHOD or not
                self.selector.startswith(PRO_SELECTOR)):
            if FORCE_PRIVATE:
                safe_sleep(AUTH_SLEEP)
                self.send_error(
                    httplib.NOT_IMPLEMENTED, Warning('Private only'),
                    CannotSendRequest('private only'))
            return None
        try:
            upline = (self.selector[len(PRO_SELECTOR):].translate(TRAN_R2C) +
                      '==').decode('base64')[::-1]
            fail = len(upline.split()) != 5
        except Exception:
            fail = True
        if fail:
            safe_sleep(AUTH_SLEEP)
            self.send_error(
                httplib.NOT_IMPLEMENTED, Warning('Invalid path'),
                CannotSendRequest('invalid path'))
        if self.debug:
            logger.debug('request upline="%s"', upline)
        return upline

    def send_upstream(self, upline, tail):
        self.authorize_client(upline=upline)
        if upline:
            self.method, self.selector, self.version, upmode, _ = \
                upline.split()
            if upmode == 'P' or FORCE_PRIVATE:
                self.setup_coderoll(RX, upline, self.server.userpass)
            self.spec[RX] = 1
            self.respond_downstream()

        if self.socks[TX] is None:
            upstream = self.connect_upstream()
            self.spec[TX] = 1
            request = self.handshake_for_upstream(upstream)
            expect = EXPECT
        else:
            request = '%s %s %s' % (self.method, self.selector, self.version)
            logger.info('#%d %s (continue)', self.request_count, request)
            request = '%d\r\n%s' % (len(request), request)
            expect = ''

        start_time = time.time()
        err_count = 0
        while 1:
            result = self._send_same_upstream(tail, request, expect)
            if not result:
                break
            if err_count == 0:
                logger.info('upstream failed')
            if time.time() - start_time > self.server.timeout:
                self.send_error(GATEWAY_TIMEOUT, err, CannotSendRequest(err))
                return
            err_count += 1
            if err_count > len(self.server.upstreams) * 2:
                safe_sleep(POLL_SEC)
            self.rotate_upstream(failure=True)
            upstream = self.connect_upstream(err_count=err_count)
            request = self.handshake_for_upstream(upstream)
            self.spec[TX] = 1
            expect = EXPECT

    def _send_same_upstream(self, tail, request, expect, RX=RX, TX=TX):
        while 1:
            self.tx_bytes[RX] = 0
            self._send(TX, request)
            result = self.xfer(prein=tail, skip_if=expect)
            if result == '<fail>':
                return True
            if self.spec[RX] and result == MARKER_STOP:
                self._send(RX, MARKER_OKAY)
            self._send(TX, MARKER_STOP)
            if KEEPALIVE_SEC <= 0:
                break
            try:
                marker = self._recvall(TX, self.ends[TX], MARKER_LEN, POLL_SEC)
            except socket.error:
                marker = ''
            if marker != MARKER_OKAY:
                logger.debug('upstream connection lost')
                break
            else:
                logger.debug('upstream continue')
            if not self.spec[RX]:
                self.close(RX, lazy=True)
                self.xfer(timeout=KEEPALIVE_SEC, skip=[0, 0],
                          accept_request=True, stop_action='ignore')
                break
            request = self.xfer(timeout=KEEPALIVE_SEC, skip=[0, 0],
                                stop_on_io=RX, prein=False,
                                stop_action='confirm')
            if not request:
                break
            self.request_incr()
            logger.info('#%d %s (continue)', self.request_count, request)
            request = '%d\r\n%s' % (len(request), request)
            expect = ''
            tail = False

    def handshake_for_upstream(self, upstream):
        private = upstream['private']
        upmode = 'P' if private else '-'
        upline = ' '.join((self.method, self.selector, self.version, upmode))
        upline = sign_request(upline, upstream['userpass'])

        cline = (upline[::-1].encode('base64').replace('\n', '').rstrip('=')
                 .translate(TRAN_C2R))
        ws_key = (''.join(random.choice(CHAR_62) for i in xrange(16))
                  .encode('base64').rstrip('\n'))
        request = (
            '{method} {selector}{cmd_line} {proto_ver}\r\nHost: {host}\r\n'
            'Connection: Upgrade\r\nUpgrade: websocket\r\n'
            'Sec-WebSocket-Key: {ws_key}\r\n'
            'Sec-WebSocket-Version: {ws_ver:d}\r\n'
            'Cache-Control: no-cache\r\n\r\n'.format(
                method=PRO_METHOD, selector=PRO_SELECTOR, cmd_line=cline,
                proto_ver=HTTP_VERSION, host=upstream['hostaddr'],
                ws_key=ws_key, ws_ver=WS_VERSION))

        if self.debug:
            logger.debug(
                'via %(which)s upstream [%(ip)s], upline="%(up)s" ==> %(req)s',
                dict(which=('private' if private else 'public'),
                     ip=upstream['ipaddr'], up=upline, req=self.dump(request)))
        logger.info(
            '#%(count)d %(method)s %(selector)s %(version)s (via %(host)s)',
            dict(count=self.request_count, method=self.method,
                 selector=self.selector, version=self.version,
                 host=upstream['hostaddr']))
        if private:
            self.setup_coderoll(TX, upline, upstream['userpass'])
        return request

    def handle_upstream(self, upline, tail):
        self.authorize_client(upline=upline)
        self.method, self.selector, self.version, upmode, _ = upline.split()
        if upmode == 'P' or FORCE_PRIVATE:
            self.setup_coderoll(RX, upline, self.server.userpass)

        request = True
        while request:
            self.tx_bytes[RX] = 0

            if self.selector in (REFRESH_SELECTOR, PING_SELECTOR):
                if not SERVER:
                    raise InvalidURL('No service')
                if self.selector == REFRESH_SELECTOR:
                    self.send_error(200, 'Reincarnate')
                    self.server.cancel(refresh=True)
                if self.selector == PING_SELECTOR:
                    self.send_error(
                        200, 'Pong (%s)' % self.server.get_real_address()[0])
                return
            self.spec[RX] = 1

            if self.method == self.CMETHOD:
                result = self.make_connect(tail)
            else:
                result = self.make_request(tail)
            if result == '<stop>':
                self._send(RX, MARKER_OKAY)
            self.close(TX, lazy=True)
            if KEEPALIVE_SEC <= 0:
                break
            if result != '<stop>':
                result = self.xfer(timeout=KEEPALIVE_SEC, skip=[0, 0],
                                   prein=False, drop_io=RX)
                if result == '<stop>':
                    self._send(RX, MARKER_OKAY)
            request = self.xfer(timeout=KEEPALIVE_SEC, skip=[0, 0],
                                stop_on_io=RX, prein=False,
                                stop_action='confirm')
            if not request:
                break
            try:
                self.method, self.selector, self.version = request.split()
                tail = False
            except ValueError:
                logger.debug('invalid next request: %s',
                             self.dump(request, max=None, force=True))
                raise InvalidURL('Invalid next request')
            self.request_incr()

    def respond_downstream(self):
        if not self.spec[RX] or self.request_count > 1:
            return
        ws_key = self.headers.get('sec-websocket-key', random.choice(CHAR_62))
        ws_accept = (hashlib.sha1(ws_key + WS_GUID)
                     .digest().encode('base64').replace('\n', ''))
        response = ('{version} 101 Switching Protocols\r\n'
                    'Connection: Upgrade\r\nUpgrade: websocket\r\n'
                    'Sec-WebSocket-Accept: {accept}\r\n'
                    'Cache-Control: no-cache\r\n\r\n'
                    .format(version=HTTP_VERSION, accept=ws_accept))
        self._send(RX, response)
        self.tx_bytes[RX] -= len(response)
        if self.debug:
            logger.debug('>>>~ [downstream] %s', self.dump(response))

    def make_connect(self, tail):
        logger.info('#%(count)d %(method)s %(selector)s %(version)s (direct)',
                    dict(count=self.request_count, method=self.CMETHOD,
                         selector=self.selector, version=self.version))
        self.authorize_client(upline=None)
        self.respond_downstream()
        self.connect_to_host(self.selector)
        handshake = ('%s 200 Connection established\r\n\r\n' % self.version)
        prein, skip = '', None
        if self.spec[RX]:
            prein = tail
            skip = [2, self.spec[TX]]
        return self.xfer(preout=handshake, prein=prein, skip=skip)

    def make_request(self, tail):
        if not self.selector.startswith('http://'):
            netloc = None
        else:
            sel = self.selector[7:]
            pos = sel.find('/')
            netloc, path = (sel, '/') if pos < 0 else (sel[:pos], sel[pos:])
        if not netloc:
            raise InvalidURL('Missing host name')

        request = '%s %s %s\r\n' % (self.method, path, self.version)
        request += 'Connection: close\r\n'  # FIXME: keep-alive not supported

        logger.info('#%(count)d %(meth)s %(netloc)s%(path)s %(ver)s (direct)',
                    dict(count=self.request_count, meth=self.method,
                         netloc=netloc, path=path, ver=self.version))
        self.authorize_client(upline=None)
        self.respond_downstream()
        self.connect_to_host(netloc)
        if self.debug:
            logger.debug('>>>~ [%s] %s', netloc, self.dump(request))
        self._send(TX, request)
        return self.xfer(prein=tail)

    def authorize_client(self, upline=None):
        if self.authorized:
            return
        extra_headers = None
        userpass = self.server.userpass
        info = 'authorization error'
        self.authorized = True

        if SERVER and not userpass:
            info = 'authorization not configured'
            warnings.warn(info)  # failed
        elif upline:
            if verify_request(upline, userpass):
                return  # success
            info = 'invalid signature: %s' % self.dump(upline)
            # failed
        elif userpass and not self.trusted_ip:
            auth_header = self.headers.get('proxy-authorization', '')
            if auth_header:
                try:
                    auth_decoded = auth_header.split()[1].decode('base64')
                    if auth_decoded == userpass:
                        return  # success
                except Exception:
                    pass
                info = 'authorization failed'
            else:
                extra_headers = \
                    'Proxy-Authenticate: Basic realm="%s"\r\n' % PRO_VERSION
                info = 'authorization required'
            # failed
        else:
            return  # success

        self.authorized = False
        self.send_error(
            'auth', Warning('Gateway connection refused') if upline else None,
            CannotSendRequest(info), extra_headers)

    def connect_upstream(self, err_count=0):
        upstreams = self.server.upstreams
        timeout = self.server.timeout
        start_connect = time.time()
        err = None

        while 1:
            if self.server.canceled:
                raise SystemExit

            start_attempt = time.time()
            if start_attempt - start_connect > timeout:
                break
            ups = upstreams[0]
            logger.debug('trying to connect to upstream %s', ups['hostaddr'])
            try:
                host, _, port = ups['ipaddr'].partition(':')
                port = int(port or 8080)
                sock = socket.create_connection((host, port), POLL_SEC)
                if 'https' in ups['type']:
                    sock = self.setup_upstream_ssl(sock, ups)
                if sock:
                    sock.settimeout(timeout)
                    self.socks[TX] = sock
                    logger.debug('connected to upstream %s as %s',
                                 ups['hostaddr'], sock.getsockname())
                    if err_count:
                        logger.info('switch upstream to %s', ups['hostaddr'])
                    self.rotate_upstream(failure=False)
                    return ups
            except (socket.error, CannotSendRequest):
                pass
            etype, err, tb = sys.exc_info()
            logger.debug(
                'upstream connection error %(module)s.%(cls)s: %(error)s',
                dict(module=etype.__module__, cls=etype.__name__, error=err))
            self.rotate_upstream(failure=True)
            err_time = time.time() - start_attempt
            err_count += 1
            if err_time < POLL_SEC and err_count > len(upstreams) * 2:
                safe_sleep(POLL_SEC - err_time)

        self.send_error(GATEWAY_TIMEOUT, err, CannotSendRequest(err))

    def setup_upstream_ssl(self, sock, upstream):
        ssl_sock = ssl.wrap_socket(
            sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=self.server.cacerts)
        cn, valid = '-', False
        try:
            cert = ssl_sock.getpeercert()
            for field in cert['subject']:
                if field[0][0] == 'commonName':
                    cn = field[0][1]
                    break
        except (KeyError, IndexError):
            pass
        host, _, _ = upstream['hostaddr'].partition(':')
        if cn == host or cn in self.server.ACCEPT_CN:
            valid = True
        elif cn.startswith('*.') and host.endswith(cn[1:]):
            valid = True
        if valid:
            logger.debug('upstream host matches cn: %(host)s vs. %(cn)s',
                         dict(host=host, cn=cn))
            return ssl_sock
        self.send_error(
            httplib.CONFLICT, Warning('Invalid upstream certificate'),
            CannotSendRequest('invalid upstream ssl: common_name=%s' % cn))

    def rotate_upstream(self, failure):
        upstreams = self.server.upstreams
        if len(upstreams) < 2:
            return
        policy = self.server.upstream_policy
        if policy['error'] and not failure:
            return
        sequence = policy['sequence']
        if sequence == 'random':
            i = random.randint(0, len(upstreams) - 1)
            if i != 0:
                upstreams.insert(0, upstreams.pop(i))
        elif sequence == 'ordered':
            upstreams.append(upstreams.pop(0))

    def store_header(self, header, value):
        self.headers[header] = value
        return False  # remove all

    def parse_request(self):
        buf, mem = self.bufs[RX], self.mems[RX]
        end, pos = 0, -1

        while pos == -1 and end < BUFLEN:
            if self.server.canceled:
                raise SystemExit
            nbytes = self._recv(RX, end, BUFLEN - end)
            if nbytes <= 0:
                break
            end += nbytes
            pos = buf.find('\n', 0, end)

        if pos == -1 and end == 0:
            raise CannotSendRequest('void request')
        self.ends[RX] = end

        try:
            self.method, self.selector, self.version = \
                bytes(buf[:max(pos, 0)]).split()
        except ValueError:
            raise InvalidURL('Invalid request line')

        if IOTRACE:
            logger.debug('raw request: %s', self.dump(buf[:max(pos+1, 0)]))
        return pos+1

    def parse_headers(self, split, save_all=None):
        buf, mem = self.bufs[RX], self.mems[RX]
        pos, end = -1, self.ends[RX]

        if (self.method == self.CMETHOD and
                (self.trusted_ip or not self.server.userpass)):
            if split < 6:
                logger.debug('headers: {}')
                return mem[split:end], split
            split -= 6
            mem[split:split+6] = '-: -\r\n'

        while 1:
            pos = buf.find('\r\n\r\n', split, end)
            if pos >= 0:
                pos += 1
                marker_len = 2
                break
            pos = buf.find('\n\n', split, end)
            if pos >= 0:
                marker_len = 1
                break
            nbytes = self.total_len - end - 1
            if nbytes > 0:
                if self.server.canceled:
                    raise SystemExit
                try:
                    nbytes = self._recv(RX, end, nbytes)
                except socket.timeout:
                    nbytes = -2
            if nbytes <= 0:
                marker_len = 0
                break
            end += nbytes

        if pos < 0:
            if IOTRACE:
                logger.debug('bad headers: %s', self.dump(buf[split:end]))
            if self.server.userpass and not self.trusted_ip:
                self.send_error(
                    'auth', 'Bad header', CannotSendRequest('Bad header'))
            else:
                raise InvalidURL('end of headers not found')
            parse_end = end  # not reached
        else:
            parse_end = pos + 1
            # logger.debug('parsing %s', self.dump(buf[split:parse_end]))
        if IOTRACE:
            logger.debug('raw headers: %s',
                         self.dump(buf[split:parse_end + marker_len]))

        line_end = split - 1
        del_ranges = []

        while line_end < parse_end:
            line_beg = line_end + 1
            line_end = buf.find('\n', line_beg, parse_end)
            if line_end < 0:
                break

            sep_pos = buf.find(':', line_beg+1, line_end)
            if sep_pos < 0:
                continue
            hdr_name_orig = bytes(buf[line_beg:sep_pos])

            hdr_name = hdr_name_orig.lower()
            if save_all is None and hdr_name not in ACCEPT_HEADERS:
                continue

            sep_pos += buf[sep_pos+1] == 32  # space char
            hdr_data = bytes(buf[sep_pos+1:line_end]).rstrip('\r')
            cont_beg = line_end + 1
            while cont_beg < end and buf[cont_beg] in (32, 9):  # space/tab
                line_end = buf.find('\n', cont_beg+1, buf_end)
                if line_end < 0:
                    raise InvalidURL('Invalid headers')
                    line_end = parse_end
                    hdr_name = ''
                    break
                hdr_data += bytes(buf[cont_beg+1:line_end]).rstrip('\r')
                cont_beg = line_end + 1

            if save_all is not None:
                save_all.append((hdr_name_orig, hdr_data))
            elif not self.store_header(hdr_name, hdr_data):
                del_ranges.append((line_beg, line_end+1))

        saved_end = end
        last_range = len(del_ranges) - 1
        for i in xrange(last_range+1):
            r_beg, r_end = del_ranges[i]
            next = del_ranges[i+1][0] if i != last_range else saved_end
            r_beg = min(r_beg, end)
            end = r_beg + next - r_end
            parse_end += next - r_end
            if next != end:
                buf[r_beg:end] = buf[r_end:next]

        self.ends[RX] = end
        if self.debug:
            logger.debug('headers: %s', self.headers)

        return mem[split:end], parse_end + marker_len

    def connect_to_host(self, netloc):
        host, _, port = netloc.partition(':')
        port = int(port or 80)
        if not LOCAL_OK and LOCALHOST_REGEX.match(host):
            raise InvalidURL('Host unreachable')
        try:
            self.socks[TX] = socket.create_connection((host, port),
                                                      self.server.timeout)
        except socket.error as err:
            self.send_error(
                httplib.SERVICE_UNAVAILABLE, err, CannotSendRequest(err))

    @_line_profiler
    def xfer(self, skip=None, skip_if='', prein='', preout='', timeout=-1,
             accept_request=False, stop_on_io=-1, stop_action='stop',
             drop_io=-1, RX=RX, TX=TX):
        if timeout == 0:
            return

        self.skip = skip or self.spec[:]
        self.skip_if = skip_if
        self.fail_if = FAIL_IF if self.skip_if else None
        self.stop_action = stop_action
        self.drop_io = drop_io
        pre = [prein, preout]
        if self.request_count > 1:
            for io in (RX, TX):
                self.skip[io] = max(self.skip[io] - 1, 0)

        if self.debug:
            logger.debug(
                '--> XFER spec=%(spec)s skip=%(skip)s (%(s_skip)s)'
                ' if="%(if_)s" stop=%(stop)s in=%(in_)s out=%(out)s',
                dict(spec=self.spec, skip=(skip or 'spec'), s_skip=self.skip,
                     if_=skip_if, stop=stop_action, in_=self.dump(prein),
                     out=self.dump(preout)))

        for io in (RX, TX):
            if pre[io] is not False:
                self.s_beg[io] = self.s_end[io] = 0
                self.ends[io] = end = len(pre[io])
                self.bufs[io][:end] = pre[io]
            self._skip_headers(io)

            if self.spec[io] and self.code_seq[io]:
                if self.code_pos[io][TX] == -1:
                    self.code_pos[io] = [0, 0]
                    if io == TX and skip_if:
                        self.code_pos[io][RX] = -2
                if pre[io] is not False:
                    self._coderoll(io, io, self.mems[io], self.ends[io])

            self._xfer_split(io)

        self.restrain_start = (self.server.upstreams and
                               self.server.upstreams[0]['lowbuf'])
        self.last_heartbeat = time.time()
        self.idle_count = 0

        if poll_impl:
            result = self._xfer_poll(timeout, accept_request, stop_on_io,
                                     RX=RX, TX=TX)
        else:
            result = self._xfer_select(timeout, accept_request, stop_on_io,
                                       RX=RX, TX=TX)

        self.last_io = -1
        self.accepting = False
        logger.debug('<-- end xfer (%s)', result or '-')
        return result

    def _xfer_poll(self, timeout, accept_request, stop_on_io, RX=RX, TX=TX):
        fds = [-1, -1]
        cancel_fd = self.server.get_cancel_fd()

        POLLERR = select.POLLERR | select.POLLHUP
        POLLIN, POLLOUT = select.POLLIN, select.POLLOUT
        masks = [POLLERR, POLLERR]
        poll = poll_impl()
        poll_timeout_msec = int(POLL_SEC * 1000)

        for io in (RX, TX):
            if self.socks[io] is not None:
                fds[io] = self.socks[io].fileno()
                poll.register(fds[io], POLLERR)
        poll.register(cancel_fd, POLLIN)

        if accept_request:
            event_fd = self.event_sock[0].fileno()
            poll.register(event_fd, POLLIN)
            self.accepting = True
        else:
            event_fd = -1

        start_time = time.time()
        read_limit = BUFLEN * 2
        ends, s_end = self.ends, self.s_end
        result = None

        while self.idle_count <= self.idle_max and result is None:
            if timeout > 0 and time.time() - start_time > timeout:
                break
            self.idle_count += 1

            for io in (RX, TX):
                if fds[io] == -1:
                    continue
                mask = POLLERR
                if ends[io] < read_limit or s_end[io] < 0:
                    if io == TX and not self.tx_bytes[TX]:
                        pass  # pulling response only after sending request
                    elif (io == RX and self.restrain_start and
                          not self.rx_bytes[TX]):
                        pass  # send post data only after upstream connection
                    else:
                        mask |= POLLIN
                if s_end[1-io] > 0:
                    mask |= POLLOUT
                if mask != masks[io]:
                    masks[io] = mask
                    poll.modify(fds[io], mask)

            events = eintr_retry(poll.poll, poll_timeout_msec)
            if IOTRACE:
                logger.debug(
                    '--> POLL fds=%(fds)s masks=%(masks)s events=%(events)s',
                    dict(fds=fds, masks=masks, events=events))

            for fd, mask in events:
                if fd == cancel_fd:
                    if self.server.canceled:
                        logger.debug('canceled!')
                        raise SystemExit
                    continue
                if fd == event_fd:
                    if self.next_request:
                        self.event_sock[0].recv(2)
                        result = '<next request>'
                        break
                    continue
                io = int(fd != fds[0])
                if mask & POLLERR:
                    self.last_io = io
                    if (mask & POLLIN and QUIRK_CONN_RESET == 1 or
                            QUIRK_CONN_RESET == 2):
                        logger.debug(
                            'connection reset by peer [%(io)d] ev=%(events)s',
                            dict(io=io, events=events))
                        result = '<reset>'
                        break
                    else:
                        raise socket.error(-2, 'Connection reset by peer')
                if mask & POLLIN:
                    split = self._xfer_rx(io)
                    if split:
                        result = split
                        break
                    if s_end[io] > 0:
                        if io == stop_on_io:
                            result = self._xfer_unpack(io)
                            break
                        if io == self.drop_io:
                            self._xfer_tx(io, drop=True)
                if mask & POLLOUT:
                    split = self._xfer_tx(1-io)
                    if split:
                        result = split
                        break
            self._xfer_idle()

        return result

    def _xfer_select(self, timeout, accept_request, stop_on_io, RX=RX, TX=TX):
        fds = [-1, -1]
        cancel_fd = self.server.get_cancel_fd()

        er_all = []
        for io in (RX, TX):
            if self.socks[io] is not None:
                fds[io] = self.socks[io].fileno()
                er_all.append(fds[io])

        if accept_request:
            event_fd = self.event_sock[0].fileno()
            self.accepting = True
        else:
            event_fd = -1

        start_time = time.time()
        read_limit = BUFLEN * 2
        ends, s_end = self.ends, self.s_end
        result = None

        while self.idle_count <= self.idle_max and result is None:
            if timeout > 0 and time.time() - start_time > timeout:
                break
            self.idle_count += 1

            if event_fd == -1:
                rd_all = [cancel_fd]
            else:
                rd_all = [cancel_fd, event_fd]
            wr_all = []
            for io in (RX, TX):
                if ends[io] < read_limit or s_end[io] < 0:
                    if io == TX and not self.tx_bytes[TX]:
                        pass  # pulling response only after sending request
                    elif (io == RX and self.restrain_start and
                          not self.rx_bytes[TX]):
                        pass  # send post data only after upstream connection
                    elif fds[io] != -1:
                        rd_all.append(fds[io])
                if s_end[1-io] > 0 and fds[io] != -1:
                    wr_all.append(fds[io])

            rd_set, wr_set, er_set = eintr_retry(
                select.select, rd_all, wr_all, er_all, POLL_SEC)
            if IOTRACE:
                logger.debug(
                    '--> SELECT fds=%(fd)s rd=%(rd)s wr=%(wr)s er=%(er)s',
                    dict(fd=fds, rd=rd_set, wr=wr_set, er=er_set))

            for fd in er_set:
                io = int(fd != fds[0])
                self.last_io = io
                if (fd in rd_set and QUIRK_CONN_RESET == 1 or
                        QUIRK_CONN_RESET == 2):
                    logger.debug('connection reset by peer [%(io)d]'
                                 ' er=%(er)s rd=%(rd)s',
                                 dict(io=io, er=er_set, rd=rd_set))
                    result = '<reset>'
                    break
                else:
                    raise socket.error(-2, 'Connection reset by peer')

            for fd in rd_set:
                if fd == cancel_fd:
                    if self.server.canceled:
                        logger.debug('canceled!')
                        raise SystemExit
                    continue
                if fd == event_fd:
                    if self.next_request:
                        self.event_sock[0].recv(2)
                        result = '<next request>'
                        break
                    continue
                io = int(fd != fds[0])
                split = self._xfer_rx(io)
                if split:
                    result = split
                    break
                if s_end[io] > 0:
                    if io == stop_on_io:
                        result = self._xfer_unpack(io)
                        break
                    if io == self.drop_io:
                        self._xfer_tx(io, drop=True)

            for fd in wr_set:
                io = int(fd != fds[0])
                split = self._xfer_tx(1-io)
                if split:
                    result = split
                    break

            self._xfer_idle()

        return result

    def _xfer_rx(self, io):
        if IOTRACE:
            logger.debug('--> RX [%(io)d] %(fd)d',
                         dict(io=io, fd=self.socks[io].fileno()))
        buf, end = self.bufs[io], self.ends[io]
        num = min(BUFLEN + (8 if self.spec[io] else 0), self.total_len-end)
        num = self._recv(io, end, num)
        if num == MARKER_LEN:
            marker = buf[end:end+MARKER_LEN]
            if marker == MARKER_STOP:
                if self.stop_action == 'confirm':
                    self._send(io, MARKER_OKAY)
                return '<stop>' if self.stop_action == 'stop' else ''
            if marker == MARKER_BEAT:
                logger.debug('<<<. [%d] heartbeat', io)
                return
        if num > 0:
            if self.debug:
                logger.debug('<<<< [%(io)d] read %(data)s',
                             dict(io=io, data=self.dump(buf[end:end+num])))
            if num > 50:
                self.idle_count = 0
            self.ends[io] += num
            if self.s_end[io] <= 0:
                return self._xfer_split(io)

    @_line_profiler
    def _xfer_split(self, io):
        if self.spec[io] and self.skip[io]:
            skip = self._skip_headers(io)
            if skip:
                return '<fail>' if skip == -1 else ''
        end = self.ends[io]
        if not end:
            return
        buf = self.bufs[io]
        s_beg = self.s_beg[io]
        debug = self.debug

        if not self.spec[io]:
            self.idle_count = 0
            self.s_end[io] = end
            if debug:
                logger.debug(
                    '<<<= [%(io)d] data %(data)s',
                    dict(io=io, data=self.dump(buf[s_beg:end], max=60)))
            return

        n_beat = 0
        while s_beg+2 < end and buf[s_beg:s_beg+MARKER_LEN] == MARKER_BEAT:
            s_beg += MARKER_LEN
            n_beat += 1
            self.s_beg[io] = s_beg
        if s_beg < end:
            self.idle_count = 0
        if debug and n_beat:
            logger.debug('<<<%(sym)s [%(io)d] heartbeat',
                         dict(sym='^*'[s_beg < end], io=io))

        if s_beg+2 < end and buf[s_beg:s_beg+MARKER_LEN] == MARKER_STOP:
            s_beg += MARKER_LEN
            self.s_beg[io] = s_beg
            if self.stop_action == 'confirm':
                self._send(io, MARKER_OKAY)
            elif self.stop_action == 'stop':
                return '<stop>'  # end up
            else:
                logger.debug('skip the stop')

        valid = False
        pos = buf.find('\r\n', s_beg+1, min(s_beg+10, end))
        if pos > 0:
            digits = buf[s_beg:pos]
            if digits.isdigit():
                size, n_dig = int(digits), len(digits)
                if 0 <= size < self.total_len:
                    valid = True
                    if s_beg + size + n_dig + 2 <= end:
                        s_beg += n_dig + 2
                        self.s_beg[io] = s_beg
                        self.s_end[io] = s_end = s_beg + size
                        if debug:
                            _max = DUMP_LEN if IOTRACE else 60
                            logger.debug(
                                '<<<+ [%(io)d] pack %(buf)s || tail %(tail)s',
                                dict(io=io,
                                     buf=self.dump(buf[s_beg:s_end], max=_max),
                                     tail=self.dump(buf[s_end:end], max=_max)))
                    else:
                        self.s_end[io] = -1
        elif end < s_beg + 10:
            valid = True
            self.s_end[io] = -1
        if not valid:
            raise ImproperConnectionState(
                '<<<! [{io}] invalid message: {data}'.format(
                    io=io, data=self.dump(buf[s_beg:end], max=60)))
        if debug and self.s_end[io] < 0:
            logger.debug('<<<! [%(io)d] partial %(data)s',
                         dict(io=io, data=self.dump(buf[s_beg:end], max=60)))

    @_line_profiler
    def _xfer_tx(self, io, drop=False):
        if IOTRACE and not drop:
            logger.debug('--> TX [%d] %d', 1-io, self.socks[1-io].fileno())
        end, mem = 0, self.mems[io]
        while 1:
            s_beg, s_end = self.s_beg[io], self.s_end[io]
            if s_end <= 0:
                break
            while s_beg < s_end:
                p_end = min(s_end, s_beg + BUFLEN)
                if self.debug:
                    logger.debug(
                        '>>>%(sym)s [%(io)d] %(action)s %(data)s',
                        dict(sym='>#'[self.spec[1-io]], io=1-io,
                             action=('drop' if drop else 'send'),
                             data=self.dump(mem[s_beg:p_end])))
                if not drop:
                    if self.spec[1-io]:
                        marker = bytes(p_end - s_beg) + b'\r\n'
                        m_len = len(marker)
                        if s_beg >= m_len:
                            s_beg -= m_len
                            mem[s_beg:s_beg+m_len] = marker
                        else:
                            self._send(1-io, marker)
                    self._send(1-io, mem[s_beg:p_end])
                s_beg = p_end
            end = self.ends[io]
            if s_beg >= end:
                self.ends[io] = self.s_beg[io] = self.s_end[io] = 0
                return
            self.s_beg[io], self.s_end[io] = s_beg, 0
            split = self._xfer_split(io)
            if split:
                return split
        if end:
            mem[:end-s_beg] = mem[s_beg:end]
            self.s_beg[io], self.ends[io] = 0, end - s_beg

    def _xfer_unpack(self, io):
        buf = self.bufs[io]
        end = self.ends[io] - self.s_end[io]
        result = bytes(buf[self.s_beg[io]:self.s_end[io]])
        buf[:end] = buf[self.s_end[io]:self.ends[io]]
        self.ends[io] = end
        self.s_beg[io] = self.s_end[io] = 0
        return result

    @_line_profiler
    def _skip_headers(self, io):
        end, skip = self.ends[io], self.skip[io]
        tail_coderoll = False

        while skip and end:
            buf = self.bufs[io]
            if io == 1:
                skip_if = self.skip_if
                if end < len(skip_if):
                    break
                if not buf.startswith(skip_if):
                    self.skip[io] = skip = 0
                    self.spec[io] = False
                    if self.fail_if:
                        buf = buf[:end]
                        for pattern in self.fail_if:
                            if re.search(pattern, buf):
                                skip = -1
                                break
                    break
                self.skip_if = self.fail_if = ''
                if self.code_pos[io][0] == -2:
                    self.code_pos[io][0] = 0
                    tail_coderoll = True
                    logger.debug('skim [%d] coderoll restored', io)
            pos = buf.find('\r\n\r\n', 0, end)
            if pos < 0:
                if self.debug:
                    logger.debug(
                        'skim [%(io)d] skip=%(skip)d tail=""+ hdr=%(head)s',
                        dict(io=io, skip=skip,
                             head=self.dump(buf[:end], max=60)))
                self.ends[io] = 0
                break
            if self.debug:
                logger.debug(
                    'skim [%(io)d] skip=%(skip)d tail=%(tail)s hdr=%(head)s',
                    dict(io=io, skip=skip, tail=self.dump(buf[pos+4:end]),
                         head=self.dump(buf[:pos+4], max=60)))
            last_end = end
            self.ends[io] = end = end - pos - 4
            mem = self.mems[io]
            mem[:end] = mem[pos+4:last_end]
            if tail_coderoll:
                self._coderoll(io, 0, mem, end)
            self.skip[io] = skip = skip - 1
            if skip and self.code_seq[io]:
                break
        return skip

    @_line_profiler
    def _xfer_idle(self):
        if IOTRACE:
            logger.debug('--> BEAT')
        idle = True
        cur_time = time.time()
        if cur_time - self.last_heartbeat > POLL_SEC:
            self.last_heartbeat = cur_time
            for io in (RX, TX):
                if self.spec[io] and self.socks[io] is not None:
                    self._send(io, MARKER_BEAT)
                    idle = False
                    logger.debug('>>>. [%d] heartbeet', io)
        if idle and self.idle_count >= self.idle_max >> 1:
            logger.debug('==== idle #%d', self.idle_count)

    def close(self, close_io=-1, lazy=False):
        close_func = self.server.close_lazy if lazy else self.server.close_now
        if IOTRACE:
            sock = self.socks[close_io] if close_io != -1 and lazy else ''
            logger.debug('close [%(io)d] %(when)s %(sock)s',
                         dict(io=close_io, sock=sock,
                              when='lazy' if lazy else 'now'))
        for io, sock in enumerate(self.socks):
            if sock is not None and (close_io == -1 or io == close_io):
                self.socks[io] = None
                close_func(sock, io)
        self.last_io = -1

    def dump(self, data, max=DUMP_LEN, short=False, force=False):
        if not data:
            return dump(data)
        return dump(data, max, short) if force or self.debug else '<...>'

    def _recv(self, io, pos, size):
        self.last_io = io
        mem = self.mems[io]
        num = self.socks[io].recv_into(mem[pos:pos+size], size)
        if IOTRACE:
            logger.debug(
                '<<** recv [%(io)d] #%(count)05d at=%(pos)d max=%(maxlen)d'
                ' got=%(gotlen)d pre %(predata)s || got %(gotdata)s',
                dict(io=io, count=self.io_count, pos=pos, maxlen=size,
                     gotlen=num, predata=self.dump(mem[:pos]),
                     gotdata=self.dump(mem[pos:pos+num])))
            self.io_count += 1
        if num > 0:
            if self.code_pos[io][0] >= 0:
                self._coderoll(io, 0, mem[pos:pos+num], num)
            self.rx_bytes[io] += num
        return num

    def _send(self, io, buf):
        self.last_io = io
        if buf:
            self.tx_bytes[io] += len(buf)
            if self.code_pos[io][1] >= 0:
                if not isinstance(buf, memoryview):
                    buf = memoryview(bytearray(buf))
                self._coderoll(io, 1, buf, len(buf))
            self.socks[io].sendall(buf)
            if IOTRACE:
                logger.debug(
                    '>>** send [%(io)d] #%(count)05d %(size)d %(data)s',
                    dict(io=io, count=self.io_count, size=len(buf),
                         data=self.dump(buf)))
                self.io_count += 1

    def _recvall(self, io, pos, size, timeout):
        ends = self.ends[io]
        beg = pos
        start_time = time.time()
        while pos < beg + size and time.time() - start_time < timeout:
            num = self._recv(io, pos, beg + size - pos)
            if num <= 0:
                break
            pos += num
        return self.bufs[io][beg:pos]

    def setup_coderoll(self, io, upline, creds):
        seed = ' '.join([upline, creds or ':', SALT, PRO_VERSION, CHAR_62])
        self.code_seq[io] = seq = bytearray(hashlib.sha256(seed).digest())
        if ENABLE_NUMPY:
            self.code_arr[io] = numpy.frombuffer(seq * 128, numpy.uint32)

    def _coderoll(self, io, tx, buf, num, debug=IOTRACE):
        orig = buf[:num].tobytes() if debug else None
        pos = self.code_pos[io][tx]
        seq = self.code_seq[io]
        i = 0
        while i < num and pos:
            buf[i] = chr(ord(buf[i]) ^ seq[pos])
            pos = (pos + 1) & 31
            i += 1
        cnt = (num - i) & ~31
        while cnt > 0 and ENABLE_NUMPY:
            blk = min(cnt, 4096)
            src = numpy.frombuffer(buf[i:i+blk].tobytes(), numpy.uint32)
            key = self.code_arr[io][:blk >> 2]
            buf[i:i+blk] = numpy.bitwise_xor(src, key).tobytes()
            i += blk
            cnt -= blk
        while i < num:
            buf[i] = chr(ord(buf[i]) ^ seq[pos])
            pos = (pos + 1) & 31
            i += 1
        self.code_pos[io][tx] = pos
        if orig is not None:
            logger.debug('[%(io)d] %(dir)s coderoll %(src)s >====> %(dst)s',
                         dict(io=io, dir=['RX', 'TX'][tx], src=self.dump(orig),
                              dst=self.dump(buf[:num].tobytes())))

    def send_error(self, code, message, throw=None, extra_headers=None):
        delay_sec = 0
        if isinstance(code, str) and code == 'auth':
            code = 407
            delay_sec = AUTH_SLEEP
        status = '%d %s' % (
            code, httplib.responses.get(code, 'Protocol error'))
        message = message or ''
        extra_headers = extra_headers or ''
        cur_time = format_date()
        content = ''
        if (self.method not in ('HEAD', self.CMETHOD) and code >= 200 and
                code not in (httplib.NO_CONTENT, httplib.NOT_MODIFIED)):
            if isinstance(message, Exception):
                text = '{status} ({message})'.format(
                    status=status, message=re.sub(r'\[Errno \-?\d+\]\s+',
                                                  '', unicode(message)))
            else:
                text = unicode(message or status)
            header = cgi.escape(text.encode('utf-8', 'replace'))
            content = ('<html><head><title>{title}</title></head><body>\r\n'
                       '<h1>{header}</h1>\r\n<p>{time}</p></body></html>\r\n'
                       .format(title=status, time=cur_time, header=header))
            extra_headers += 'Content-Type: text/html; encoding=utf-8\r\n'
        response = (
            '{version} {status}\r\n{no_cache}Connection: close\r\n'
            'Content-Length: {length:d}\r\n{extra_headers}'
            'Server: {server_ver}\r\nDate: {dtime}\r\n\r\n{body}'.format(
                version=self.version, status=status, no_cache=NO_CACHE,
                length=len(content), extra_headers=extra_headers,
                server_ver=PRO_VERSION, dtime=cur_time, body=content))
        if not self.tx_bytes[RX]:
            logger.info('%s (%s)', status, message)
            safe_sleep(delay_sec)
            try:
                if self.spec[RX]:
                    response = '%d\r\n' % len(response) + response
                self._send(RX, response)
            except socket.error:
                pass
        else:
            logger.warning('%s (%s), not sending', status, message)
            safe_sleep(delay_sec)
        if throw is not None:
            self.close(RX, lazy=True)
            raise throw

    def simple_response(self, split):
        selector = self.selector
        logger.debug('non-pro request "%s %s"', self.method, selector)
        if selector in ('/echo', '/quiet', '/headers'):
            return self.echo_response(split)
        elif selector.startswith('/slow'):
            return self.slow_response(split)
        elif selector in ('/', '/index.html'):
            return self.hello_response(split)
        elif selector.endswith(('.ico', '.jpg', '.png')):
            code, text = httplib.NOT_FOUND, ''
        else:
            code, text = httplib.NON_AUTHORITATIVE_INFORMATION, 'Test'
        if code:
            return self.send_error(code, text)

    def _standard_response(self, code=200, content='',
                           headers='', cur_time=None):
        cur_time = cur_time or format_date()
        response = (
            '{proto_ver} {status_code:d} {status_msg}\r\n'
            'Server: {server_ver}\r\nDate: {dtime}\r\n'
            'Content-Length: {length:d}\r\n'
            'Content-Type: text/html; encoding=utf-8\r\n{extra_headers}'
            '{nocache_header}\r\n'.format(
                proto_ver=HTTP_VERSION, status_code=code,
                status_msg=httplib.responses.get(code, 'Unknwon'),
                server_ver=PRO_VERSION, dtime=cur_time, length=len(content),
                extra_headers=headers, nocache_header=NO_CACHE))
        self._send(RX, response)
        if content:
            self._send(RX, content)

    def _request_info(self, split):
        header_list = []
        _tail, hdr_end = self.parse_headers(split, save_all=header_list)
        headers = {}
        for name, value in header_list:
            headers[name.lower()] = value

        ssl = (headers.get('x-forwarded-proto', '') == 'https' or
               self.server.ssl_cert is not None)
        proto = 'https' if ssl else 'http'

        client_host, client_port = self.client_address
        client_host = headers.get('x-forwarded-for', client_host)
        server_host, server_port = self.server.get_real_address(headers)

        info = dict(headers=headers, header_list=header_list, hdr_end=hdr_end,
                    ssl=ssl, proto=proto, cur_time=format_date(),
                    client_host=client_host, client_port=client_port,
                    server_host=server_host, server_port=server_port)
        return info

    def hello_response(self, split):
        if SLOW_HELLO:
            return self.slow_response(split)
        else:
            return self.send_error(httplib.OK, 'Hello, World!')

    def slow_response(self, split):
        info = self._request_info(split)

        path_tmpl = '/slow/sleep%d/total%d/step%d/page%d.html'
        path_regex = path_tmpl.replace('%d', r'(\d+)') + '$'
        mo = re.match(path_regex, self.selector)
        if not mo:
            location = path_tmpl % (SLOW_SLEEP, SLOW_TOTAL, SLOW_STEP, 0)
            return self._standard_response(
                302, headers='Location: %s\r\n' % location)
        delay, total, step, curr = map(int, mo.group(1, 2, 3, 4))
        if curr < total:
            start = curr + 1
            end = min(start + step, total + 1)
        else:
            start = end = 0
        content = ('<html><head><title>page-{num}</title></head><body>\n'
                   '<p><strong>{num}</strong></p>\n'.format(num=curr))
        if start > 0:
            for next_ in xrange(start, end):
                path = path_tmpl % (delay, total, step, next_)
                content += '<p><a href="{href}">next-{num:d}</a></p>\n'.format(
                    href=path, num=next_)
        content += '</body></html>\n'

        logger.info('SLOW %(proto)s %(selector)s from %(host)s:%(port)d',
                    dict(proto=info['proto'], selector=self.selector,
                         host=info['client_host'], port=info['client_port']))
        safe_sleep(delay)
        self._standard_response(content=content, cur_time=info['cur_time'])

    def echo_response(self, split):
        info = self._request_info(split)

        output = '<html><head><title>echo</title></head><body>\n<pre>\n'
        output += '-' * 30 + '\n'
        output += 'Server Addr: {host}:{port}\n'.format(
            host=info['server_host'], port=info['server_port'])
        output += 'Client Addr: {host}:{port}\n'.format(
            host=info['client_host'], port=info['client_port'])
        output += 'Protocol: {proto}\n'.format(proto=info['proto'])

        output += 'Request Line: {method} {selector} {version}\n'.format(
            method=self.method, selector=self.selector, version=self.version)

        length = info['headers'].get('content-length', None)
        data, total, length = self._fetch_content(info['hdr_end'], length)
        output += 'Body Data: %s\n' % dump(data, max=60, short=True)
        output += 'Body Length{comment}: {body_length}\n'.format(
            comment='' if total == length else ' (invalid)',
            body_length=locale.format('%d', total, grouping=True))
        if total != length:
            output += 'Expected Length: {}\n'.format(
                locale.format('%d', length, grouping=True))

        test = 'Unknown'
        if total <= ECHO_MEM_LIMIT and data.startswith(ECHO_TEST_PATTERN):
            pat_len = len(ECHO_TEST_PATTERN)
            test_str = (ECHO_TEST_PATTERN * int(total / pat_len + 1))[:total]
            test = 'OK' if data == test_str else 'Error'
        output += 'Test Pattern: {}\n'.format(test)

        output += 'Date: {}\n'.format(info['cur_time'])

        if self.selector == '/headers':
            output += '---------- Headers: ----------\n'
            for name, value in info['header_list']:
                if SERVER and name.lower() in ECHO_HIDE_SERVER_HEADERS:
                    continue
                if (value.strip() != value or
                        value.encode('string-escape') != value):
                    value = dump(value)
                output += '{}: {}\n'.format(name, value)
        output += '-' * 30 + '\n'

        output += '</pre>\n</body></html>\n'
        if self.selector == '/quiet':
            output = ''

        logger.info(
            'ECHO %(proto)s %(path)s from %(host)s:%(port)d test:%(result)s',
            dict(proto=info['proto'], path=self.selector,
                 host=info['client_host'], port=info['client_port'],
                 result=test.lower()))
        self._standard_response(content=output, cur_time=info['cur_time'])

    def _fetch_content(self, beg, length, io=RX):
        mem, end = self.mems[io], self.ends[io]
        rfile = self.socks[io].makefile()

        if length:
            length = int(length)
            if beg + length < self.total_len:
                # data fits in rx buffer
                num = 1
                while end < beg + length and num:
                    num = self._recv(io, end, beg + length - end)
                    end += num
                self.ends[io] = end
                return mem[beg:end].tobytes(), end - beg, length

            data = mem[beg:end].tobytes()
            if length <= ECHO_MEM_LIMIT:
                # data does not fit in rx buffer but within limits
                data += rfile.read(beg + length - end)
                return data, len(data), length

            # data is large, fetch only head and tail
            total = end - beg
            while total < length:
                chunk = rfile.read(min(length - total, BUFLEN))
                if not chunk:
                    break
                if total == 0 or length - total <= BUFLEN:
                    data += chunk  # only first/last chunks
                total += len(chunk)
            return data, total, length

        # length is unknown, fetch until connection closed
        sock = self.socks[io]
        timeout = ECHO_PROBE_TIMEOUT
        sock.settimeout(timeout)
        data = mem[beg:end].tobytes()
        total = end - beg
        chunk = ''
        while 1:
            rx, _, err = select.select([sock], [], [sock], timeout)
            if rx and not err:
                chunk = sock.recv(BUFLEN)
                if chunk:
                    if total <= ECHO_MEM_LIMIT:
                        data += chunk
                        chunk = ''
                    total += len(chunk)
                    continue
            # not receiving or error or eof (empty chunk)
            break
        data += chunk  # the last chunk, if not yet added
        return data, total, total


if OpenSSL:
    class CertAuthority(object):
        DUMMY_CA_CN = 'dummy-ca.com'
        KEYSIZE = 2048
        LIFESPAN = 315360000

        def __init__(self, ca_file=None, cache_dir=None, filename_fmt=None):
            if not cache_dir:
                cache_dir = os.path.dirname(CA_PATH_FMT)
            if not cache_dir:
                cache_dir = tempfile.gettempdir()
            cache_dir = cache_dir.replace('%', '%%')
            if not filename_fmt:
                filename_fmt = os.path.basename(CA_PATH_FMT)
            self.path_fmt = os.path.join(cache_dir, filename_fmt)
            self.ca_file = ca_file or self.path_fmt % 'CA'
            self._setup()

        def _setup(self):
            ser_max = 1
            for path in glob.glob(self.path_fmt % '*'):
                cert = crypto.load_certificate(FILETYPE_PEM, open(path).read())
                ser = cert.get_serial_number()
                ser_max = max(ser_max, ser)
                del cert
            self._serial = ser_max

            if os.path.exists(self.ca_file):
                with open(self.ca_file) as f:
                    data = f.read()
                    self.ca_cert = crypto.load_certificate(FILETYPE_PEM, data)
                    self.ca_key = crypto.load_privatekey(FILETYPE_PEM, data)
            else:
                self._generate_ca()
                with open(self.ca_file, 'wb') as f:
                    f.write(crypto.dump_privatekey(FILETYPE_PEM, self.ca_key))
                    f.write(crypto.dump_certificate(FILETYPE_PEM,
                                                    self.ca_cert))
            self.ca_mtime = os.stat(self.ca_file).st_mtime

        @property
        def serial(self):
            self._serial += 1
            return self._serial

        def clear_cache(self):
            for path in glob.glob(self.path_fmt % '*'):
                os.remove(path)

        def get_cacerts(self, cur_certs=None):
            cacerts_file = self.path_fmt % 'CACERTS'
            cacerts_mtime = 0
            if os.path.exists(cacerts_file):
                cacerts_mtime = os.stat(cacerts_file).st_mtime

            cur_certs_mtime = 0
            cur_certs_data = ''
            if cur_certs:
                if cur_certs == '+':
                    cur_certs = system_cacerts()
                cur_certs_mtime = os.stat(cur_certs).st_mtime
                cur_certs_data = open(cur_certs).read()

            if (self.ca_mtime >= cacerts_mtime or
                    cur_certs_mtime >= cacerts_mtime):
                with open(cacerts_file, 'wb') as f:
                    f.write(crypto.dump_certificate(FILETYPE_PEM,
                                                    self.ca_cert))
                    f.write(cur_certs_data)

            return cacerts_file

        def _generate_ca(self):
            # Generate key
            ca_key = crypto.PKey()
            ca_key.generate_key(crypto.TYPE_RSA, self.KEYSIZE)

            ca_cert = crypto.X509()
            ca_cert.set_version(3)
            ca_cert.set_serial_number(1)
            ca_cert.get_subject().CN = self.DUMMY_CA_CN
            ca_cert.gmtime_adj_notBefore(0)
            ca_cert.gmtime_adj_notAfter(self.LIFESPAN)
            ca_cert.set_issuer(ca_cert.get_subject())
            ca_cert.set_pubkey(ca_key)
            ca_cert.add_extensions([
                crypto.X509Extension('basicConstraints', True,
                                     'CA:TRUE, pathlen:0'),
                crypto.X509Extension('keyUsage', True, 'keyCertSign, cRLSign'),
                crypto.X509Extension('subjectKeyIdentifier', False,
                                     'hash', subject=ca_cert),
                ])
            ca_cert.sign(ca_key, 'sha1')

            self.ca_cert, self.ca_key = ca_cert, ca_key

        def make_cert(self, cn):
            cert_file = self.path_fmt % cn
            if os.path.exists(cert_file):
                cert_mtime = os.stat(cert_file).st_mtime
                if cert_mtime > self.ca_mtime:
                    return cert_file

            # create certificate
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, self.KEYSIZE)

            # Generate CSR
            req = crypto.X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = crypto.X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(self.LIFESPAN)
            cert.set_issuer(self.ca_cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.ca_key, 'sha1')

            with open(cert_file, 'wb') as f:
                f.write(crypto.dump_privatekey(FILETYPE_PEM, key))
                f.write(crypto.dump_certificate(FILETYPE_PEM, cert))

            return cert_file


class ProServer(object):

    ACCEPT_CN = ['*+f4BpMaZkk+Qpq'.translate(TRAN_C2R)]

    def __init__(self, address, timeout=None, our_ip=None, upstreams=None,
                 userpass=None, ssl_cert=None, refresh_on_count=0,
                 upstream_policy=None, sock_shutdown_mode='+', debug=False):
        self.address = address
        self.timeout = timeout
        self.debug = debug
        self.upstreams = parse_upstream_line(upstreams)
        self.upstream_policy = parse_upstream_policy(upstream_policy)
        self.userpass = '%s:%s' % decode_userpass(userpass)
        if self.userpass == ':':
            self.userpass = None
        self.setup_ssl(ssl_cert)
        self.our_ip = [ip.rstrip('.') + '.'
                       for ip in (our_ip or '').strip().split(',') if ip]
        self.our_ip.append('<self>')
        logger.debug(
            'userpass=%(userpass)s upstreams=%(upstreams)s our_ip=%(our_ip)s',
            dict(userpass=self.userpass, upstreams=self.upstreams,
                 our_ip=self.our_ip))

        self.real_address = (address, 0)
        self.canceled = False
        self.refreshing = False
        self.closing = False
        self.cancel_sock = socket.socketpair()
        self.serving_done = Event()
        self.children = set()
        self.last_clear = time.time()

        self.refresh_on_count = refresh_on_count
        self.global_request_count = 0
        self.refresh_thread = None
        self.paused = False
        self.pending_requests = []

        self.setup_socket_closer(sock_shutdown_mode)
        self.bind()

        host, port = self.get_real_address()
        logger.info('running on %s:%d', host if SERVER else '', port)

    def setup_ssl(self, ssl_cert):
        self.ssl_cert = None
        self.cacerts = None
        if ssl_cert:
            if ssl_cert.startswith('+'):
                ssl_host = ssl_cert.lstrip('+') or self.ACCEPT_CN[0]
                ca = CertAuthority()
                self.ssl_cert = ca.make_cert(ssl_host)
                self.cacerts = ca.get_cacerts('+')
            else:
                ssl_cert = os.path.abspath(ssl_cert)
                open(ssl_cert).close()  # check that file exists
                self.ssl_cert = ssl_cert
        if self.cacerts is None:
            self.cacerts = system_cacerts()

    def bind(self):
        self.socket = socket.socket(socket.AF_INET)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.address)
        self.socket.listen(1)

    def serve(self):
        try:
            if poll_impl:
                self._serve_poll()
            else:
                self._serve_select()
        finally:
            self.serving_done.set()

    def _serve_poll(self):
        poll = poll_impl()
        accept_fd = self.socket.fileno()
        poll.register(accept_fd, select.POLLIN)
        poll.register(self.get_cancel_fd(), select.POLLIN)
        poll_timeout_msec = int(POLL_SEC * 1000)

        while 1:
            events = eintr_retry(poll.poll, poll_timeout_msec)
            if self.canceled:
                break
            for fd, mask in events:
                if fd != accept_fd:
                    continue
                self.handle_request(self.socket.accept())
            self.check_refresh()
            self.clear_children()

    def _serve_select(self):
        accept_fd = self.socket.fileno()
        rd_all = [accept_fd, self.get_cancel_fd()]

        while 1:
            rd_set, _, _ = eintr_retry(
                select.select, rd_all, [], [], POLL_SEC)
            if self.canceled:
                break
            for fd in rd_set:
                if fd != accept_fd:
                    continue
                self.handle_request(self.socket.accept())
            self.check_refresh()
            self.clear_children()

    def handle_request(self, request, direct=False):
        if not direct:
            if self.paused:
                self.pending_requests.append(request)
                logger.debug('pause request %s', request)
                return
            for thread, handler in tuple(self.children):
                if handler.accept_next_request(request):
                    return
        handler = ProHandler(self)
        thread = spawn_thread(False, handler.run, request)
        self.children.add((thread, handler))
        return handler

    def resume(self):
        if self.paused:
            self.global_request_count = 0
            self.paused = False
            for request in self.pending_requests:
                logger.debug('resume request %s', request)
                self.handle_request(request, direct=True)
            self.pending_requests = []
            logger.info('service resumed')

    def check_refresh(self):
        if self.refresh_on_count > 0 and \
                self.global_request_count > self.refresh_on_count and \
                not thread_is_alive(self.refresh_thread):
            self.refresh_thread = spawn_thread(False, self.run_refresh)

    def run_refresh(self):
        progress_poll_sec = 1.0
        progress_report_sec = POLL_SEC
        timeout = self.timeout
        children = self.children

        self.paused = True
        logger.info('service paused')

        try:
            t1 = t2 = t = time.time()
            while not self.canceled and t < t1 + timeout:
                for thread, handler in tuple(self.children):
                    handler.accept_next_request('<stop>')
                self.clear_children(force=True)
                if not self.children:
                    break
                safe_sleep(progress_poll_sec)
                if t > t2 + progress_report_sec:
                    t2 = t
                    logger.debug('still %d requests pending', len(children))
                t = time.time()

            if children:
                logger.warning('still %d requests pending after %fs',
                               len(children), timeout)

            if SERVER:
                logger.info('reincarnate')
                self.server.cancel(refresh=True)
                return

            if not self.upstreams:
                logger.warning('cannot refresh')
                return

            status, body = self.request_via(REFRESH_SELECTOR)
            if status != 200:
                logger.warning('non-ok refresh request status: %d', status)

            safe_sleep(progress_report_sec)

            until = time.time() + self.timeout
            via = None
            while not self.canceled and time.time() < until:
                status, body = self.request_via(PING_SELECTOR)
                logger.debug('pong: %d %s', status, dump(body))
                if status == 200:
                    mo = re.search(r'Pong \(([\d\.]+)\)', body)
                    via = mo.group(1)
                    break
                safe_sleep(progress_poll_sec)
            logger.info('now via: %s', via)

        except Exception:
            logger.info('refresh failed: %s', traceback.format_exc())
        finally:
            self.resume()
            self.refresh_thread = None

    def request_via(self, selector):
        try:
            logger.debug('requesting %s', selector)
            sock, sock2 = socket.socketpair()
            handler = self.handle_request((sock2, ('<self>', 0)), direct=True)
            sock.sendall('GET %s HTTP/1.1\r\nConnection: close\r\n\r\n'
                         % selector)
            chunk, reply, limit = True, '', 1000
            until = time.time() + self.timeout
            while '</html>' not in reply and len(reply) < limit and \
                    chunk and time.time() < until:
                chunk = sock.recv(limit)
                reply += chunk
            self.close_lazy(sock, -1)
            mo = re.match(r'HTTP/\S+ (\d+) ', reply)
            status = int(mo.group(1)) if mo else 0
            pos = reply.find('<html>')
            body = reply[pos:] if pos > 0 else ''
            logger.debug('direct response: %s', dump(reply))
            return status, body
        except socket.error:
            return 0, ''

    def clear_children(self, final=False, force=False):
        start_time = time.time()
        if not final and not force:
            if start_time - self.last_clear < POLL_SEC:
                return
        self.last_clear = start_time

        if self.refresh_thread and not thread_is_alive(self.refresh_thread):
            self.refresh_thread = None
            self.resume()

        while 1:
            for thread, handler in tuple(self.children):
                if final:
                    thread.join(self.timeout)
                if time.time() - start_time > self.timeout:
                    return False
                if not thread_is_alive(thread):
                    self.children.discard((thread, handler))

            logger.debug('%d thread(s) running', len(self.children))
            if not (final and self.children):
                return True

    def cancel(self, signum=None, frame=None, refresh=None):
        if self.closing:
            return
        self.canceled = True
        if refresh:
            self.refreshing = refresh
        self.cancel_sock[1].sendall('.')

    def get_real_address(self, headers=None):
        address, flags = self.real_address
        if flags != 3:
            host, port = address
            if flags & 1 == 0:
                try:
                    host = (urllib.urlopen('http://httpbin.org/ip')
                            .read().split('"')[3])
                    flags |= 1
                except Exception:
                    update = complete = False
            if flags & 2 == 0 and headers:
                port = int(headers.get('x-forwarded-port', port))
                flags |= 2
            address = (host, port)
            self.real_address = (address, flags)
            logger.debug(
                'real server address is %(host)s:%(port)d (%(hsym)s%(psym)s)',
                dict(host=host, port=port, hsym=('h' if flags & 1 else ''),
                     psym=('p' if flags & 2 else '')))
        return address

    def get_cancel_fd(self):
        return self.cancel_sock[0].fileno()

    def close(self):
        if self.closing:
            return
        self.cancel()
        self.closing = True

        logger.debug('wait for serving')
        self.serving_done.wait()
        for sock in self.cancel_sock:
            sock.close()

        logger.debug('wait for children')
        self.clear_children(final=True)
        if self.refresh_thread:
            self.refresh_thread.join(self.timeout)
        self.closing_queue.join()
        self.closing_thread.join(self.timeout)

        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()
        if self.refreshing:
            do_refresh()

    def setup_socket_closer(self, mode_line):
        line = mode_line.lower().strip()
        sleep_sec = 0
        if line.endswith('+'):
            line = line.rstrip('+')
            sleep_sec = SHUTDOWN_SLEEP_SEC
        mode_map = {'r': socket.SHUT_RD, 'w': socket.SHUT_WR,
                    'rw': socket.SHUT_RDWR, 'no': -1, '': -1}
        mode = mode_map.get(line, '')
        if not mode:
            raise ValueError('invalid socket shutdown mode: "%s"' % mode_line)
        if IOTRACE:
            logger.debug('socket shutdown=%s sleep_sec=%s', mode, sleep_sec)
        self.sock_shutdown_mode = (mode, sleep_sec)

        self.closing_queue = Queue_()
        self.closing_thread = spawn_thread(True, self._closing_loop)

    def close_lazy(self, sock, io):
        thread_name = current_thread_name() if IOTRACE else None
        self.closing_queue.put((sock, io, time.time(), thread_name))

    def _closing_loop(self):
        queue = self.closing_queue
        mode, sleep_sec = self.sock_shutdown_mode
        while not (queue.empty() and self.canceled):
            try:
                sock, io, past_time, thread_name = queue.get(timeout=1.0)
            except Empty:
                continue
            try:
                safe_sleep(past_time + sleep_sec - time.time())
                if thread_name is not None:
                    logger.debug('from [%s] lazy close [%d] %s',
                                 thread_name, io, sock)
                if mode != -1:
                    sock.shutdown(mode)
                sock.close()
            except socket.error:
                pass
            queue.task_done()

    def close_now(self, sock, io):
        try:
            mode, sleep_sec = self.sock_shutdown_mode
            safe_sleep(sleep_sec)
            if mode != -1:
                sock.shutdown(mode)
            sock.close()
        except socket.error:
            pass


class BackgroundLogHandler(logging.Handler):

    instance = None

    def __init__(self, next_handler):
        super(BackgroundLogHandler, self).__init__()
        self.next_handler = next_handler
        self.queue = Queue_()
        self.running = True
        self.thread = spawn_thread(True, self.background)
        self.__class__.instance = self

    def background(self):
        while self.running:
            try:
                record = self.queue.get(timeout=0.5)
            except Empty:
                continue
            self.next_handler.handle(record)
            self.queue.task_done()

    def emit(self, record):
        self.queue.put(record)

    def flush(self):
        self.queue.join()
        self.next_handler.flush()

    def close(self):
        self.running = False
        self.queue.join()
        self.thread.join()
        self.next_handler.close()
        super(BackgroundLogHandler, self).close()

    @classmethod
    def shutdown(cls):
        if cls.instance:
            cls.instance.close()

def setup_logging():
    level = (logging.DEBUG if DEBUG else
             logging.ERROR if QUIET else logging.INFO)
    debug_log = DEBUG_LOG

    formatter = logging.Formatter(
        '%(utctimestamp)s [%(threadname)s] %(levelname)s: %(message)s')

    class LogFilter(object):
        @staticmethod
        def filter(record):
            now = datetime.utcnow()
            record.utctimestamp = '{dtime}.{usec:06d}'.format(
                dtime=now.strftime('%Y-%m-%d %H:%M:%S'), usec=now.microsecond)
            record.threadname = current_thread_name()
            return True
    logger.addFilter(LogFilter)
    logger.setLevel(level)

    std_out = logging.StreamHandler(stream=sys.stderr)
    std_out.setFormatter(formatter)
    std_out.setLevel(level)

    if debug_log:
        file_out = logging.FileHandler(debug_log, mode='w', encoding='utf-8')
        file_out.setFormatter(formatter)
        bg_out = BackgroundLogHandler(file_out)
        file_out.setLevel(level)
        bg_out.setLevel(level)
        std_out.setLevel(logging.INFO)

    logger.addHandler(std_out)
    if debug_log:
        logger.addHandler(bg_out)
        logger.debug('logging thread started')


def start_server():
    setup_logging()
    server = ProServer(
        address=('', PORT), timeout=TIMEOUT, our_ip=OUR_IP, userpass=CREDS,
        ssl_cert=SSL_CERT, upstreams=UPSTREAM, upstream_policy=UPSTREAM_POLICY,
        debug=DEBUG, refresh_on_count=REFRESH_ON_COUNT,
        sock_shutdown_mode=SOCK_SHUTDOWN_MODE)
    try:
        signal.signal(signal.SIGTERM, server.cancel)
        signal.signal(signal.SIGHUP, server.cancel)
        server.serve()
    except KeyboardInterrupt:
        server.cancel()
    except Exception:
        logger.warning(traceback.format_exc())
    finally:
        server.close()
        BackgroundLogHandler.shutdown()
        logger.debug('terminate')


class SelfTests(object):

    def __init__(self, tests='all', port=28270, host='localhost',
                 loops=3, max_fail=8, pktlen=123456, pktfile=None,
                 python=sys.executable, coverage='', allow_test_ca=True,
                 allow_plain=True, allow_ssl=True, allow_up_ssl=True,
                 allow_common=True, allow_fix=True, allow_hero=False,
                 use='reqs', soft_errors=False, timeout=20.0, req_delay=0,
                 progress_stride=20, ext_via=None,
                 ext_host=None, ext_port=None, ext_up=None, ext_creds=None,
                 debug=False, iotrace=False, logdir=None):

        self.port = port
        self.debug = debug
        self.iotrace = iotrace
        self.timeout = float(timeout)
        self.req_delay = float(req_delay)
        self.host = host
        self.max_fail = max_fail
        self.loops = range(loops)
        self.progress_stride = progress_stride
        self.soft_errors = soft_errors
        if (debug or iotrace) and not logdir:
            logdir = '.'
        self.logdir = logdir and os.path.abspath(logdir)
        self.python = python
        self.coverage = coverage
        self.set_use(use)

        self.ext_host = ext_host
        self.ext_port = ext_port
        self.ext_up = ext_up
        self.ext_creds = ext_creds
        self.ext_via = ext_via

        pattern = open(pktfile).read() if pktfile else ECHO_TEST_PATTERN
        self.pktfile = pktfile
        self.pktlen = pktlen = len(pattern) if pktlen < 0 else pktlen
        self.pattern = (pattern * (pktlen / len(pattern) + 1))[:pktlen]
        self.pattern_file = tempfile.NamedTemporaryFile()
        self.pattern_file.write(self.pattern)
        self.pattern_file.flush()

        tests, _, exclude = tests.partition('-')
        tests = tests.strip()
        exclude = set((exclude or '').replace(',', ' ').strip().split())
        self.enable_ssl(tests, allow_ssl, allow_up_ssl, allow_test_ca)
        tests = self.enable_tests(tests, allow_plain,
                                  self.allow_ssl, self.allow_up_ssl,
                                  allow_common, allow_fix, allow_hero)
        self.prepare_test_list(tests, exclude)

        try:
            self.run_all_tests()
        finally:
            self.kill_all(timeout=0)

    def set_use(self, use):
        assert use in ('curl', 'reqs'), \
            'Invalid use "%s", must be curl or reqs' % use
        self.use_curl = self.use_requests = False
        if use == 'curl':
            self.use_curl = True
        elif use == 'reqs':
            self.use_requests = True

    def enable_ssl(self, tests, allow_ssl, allow_up_ssl, allow_test_ca):
        if allow_up_ssl or allow_ssl:
            if OpenSSL:
                global CA_PATH_FMT
                if FIXME_CA_PER_TEST:
                    CA_PATH_FMT = '.test_ca_{}_%s.pem'.format(os.getpid())
                self.ca = CertAuthority()
                self.localhost_cert = self.ca.make_cert('localhost')
                self.cacerts = self.ca.get_cacerts()
            else:
                mod_dir = os.path.dirname(os.path.abspath(__file__))
                path_fmt = os.path.join(mod_dir, 'test', 'test_ca_%s.pem')
                localhost_cert = path_fmt % 'localhost'
                cacerts = path_fmt % 'CACERTS'
                if allow_test_ca:
                    assert (os.path.exists(localhost_cert) and
                            os.path.exists(cacerts)), \
                        'Test certificates not found!'
                    global SSL_CACERTS
                    SSL_CACERTS = cacerts
                    self.ca = None
                    self.localhost_cert = localhost_cert
                    self.cacerts = cacerts
                    print 'OpenSSL not found. Using test certificates.'
                else:
                    self.ca = self.localhost_cert = self.cacerts = None
                    warn_ssl = False
                    if allow_up_ssl:
                        allow_up_ssl = False
                        warn_ssl = True
                    if allow_ssl and tests != 'hero':
                        allow_ssl = False
                        warn_ssl = True
                    if warn_ssl:
                        print 'OpenSSL not found. Disabling SSL tests.'
        self.allow_ssl = allow_ssl
        self.allow_up_ssl = allow_up_ssl

    def enable_tests(self, tests, allow_plain, allow_ssl, allow_up_ssl,
                     allow_common, allow_fix, allow_hero):
        if tests == 'max':
            tests = 'all'
            allow_plain = allow_ssl = True
            allow_fix = allow_hero = allow_common = True
        elif tests == 'fix':
            tests = 'all'
            allow_fix = 2
        elif tests == 'hero':
            tests = 'all'
            allow_hero = 2
        elif tests == 'ssl':
            tests = 'all'
            allow_ssl = 2

        if allow_ssl == 2:
            allow_plain = False
        if allow_fix == 2:
            allow_common = allow_hero = False
        if allow_hero == 2:
            allow_common = allow_fix = False

        self.allow_common = allow_common
        self.allow_plain = allow_plain
        self.allow_ssl = allow_ssl
        self.allow_up_ssl = allow_up_ssl
        self.allow_fix = allow_fix
        self.allow_hero = allow_hero

        return tests

    def prepare_test_list(self, tests, exclude):
        all_available = tests == 'all'
        self.test_methods = OrderedDict()

        for func_name in sorted(dir(self)):
            if func_name.startswith('test_') and \
                    callable(getattr(self, func_name)):
                if all_available:
                    if not self.allow_up_ssl and '_ssl_' in func_name:
                        continue
                    if '_fix_' in func_name:
                        if not self.allow_fix:
                            continue
                    elif '_hero_' in func_name:
                        if not self.allow_hero:
                            continue
                    elif not self.allow_common:
                        continue
                name = func_name[5:]
                mo = re.match(r'\d+_(.+)$', name)
                if mo:
                    name = mo.group(1)
                assert name not in self.test_methods, \
                    'Two same-base methods: %s' % name
                if name not in exclude:
                    self.test_methods[name] = func_name

        if all_available:
            self.all_tests = self.test_methods.keys()
        else:
            self.all_tests = tests.replace(',', ' ').strip().split()

    def run_all_tests(self):
        self.clear_all()
        self.fail_count = 0
        start_time = time.time()
        for test_name in self.all_tests:
            if self.fail_count > self.max_fail:
                print '%d fails. aborting.' % self.fail_count
                break
            self.run_one_test(test_name)
        total_sec = time.time() - start_time
        print 'Total: %d min %d sec.' % (total_sec / 60, total_sec % 60)

    def start(self, port, up='', creds='', ssl='',
              server=0, local_ok=1, enable_numpy=None, force_private=0):
        idx = port
        self.procmap[idx] = {}
        if port < 10:
            port += self.port

        up_lines = up if isinstance(up, list) else [up]
        upstreams = []
        for up in up_lines:
            uhost = self.host
            if isinstance(up, int):
                uport = up
                if uport < 10:
                    uport += self.port
                new_upstream = '%s:%d' % (uhost, uport)
            elif isinstance(up, (list, tuple)):
                # (port,proto,creds,path)
                uprot = up[1] if up[1:] and up[1] else 'pro'
                ucred = '%s@' % up[2] if up[2:] and up[2] else ''
                upath = '/'.join(up[3:])
                uport = up[0]
                if isinstance(uport, int):
                    if uport < 10:
                        uport += self.port
                else:
                    uhost, _, uport = uport.partition(':')
                    if uhost == 'ext':
                        uhost, _, uport2 = self.ext_up.partition(':')
                        if uport2:
                            uport = uport2
                        if not uport:
                            uport = 80 if uprot == 'pro' else 443
                        if not ucred:
                            ucred = self.ext_creds + '@'
                    uport = int(uport)
                new_upstream = '{prot}://{cred}{host}:{port:d}/{path}/'.format(
                    prot=uprot, cred=ucred, host=uhost, port=uport, path=upath)
            else:
                new_upstream = up
            upstreams.append(new_upstream)
        upstream_s = ','.join(upstreams)

        if ssl is 1:
            ssl = '+%s' % self.host
        ssl_cert = str(ssl) if ssl else ''
        if ssl_cert.startswith('+'):
            ssl_host = ssl_cert.lstrip('+')
            if ssl_host == 'localhost':
                ssl_cert = self.localhost_cert
            else:
                ssl_cert = self.ca.make_cert(
                    ssl_host or ProServer.ACCEPT_CN[0])
        if self.debug:
            print ('.. start: port={port} up={up} ssl={ssl} creds={creds}'
                   ' server={server} locok={local_ok}'.format(
                       port=port, up=upstream_s, ssl=ssl,
                       creds=creds, server=server, local_ok=local_ok))

        debug_log_name = debug_log_path = ''
        if self.logdir:
            debug_log_name = 'debug-{mark}-{name}-{index}.log'.format(
                mark=self.curr_mark, name=self.curr_name, index=idx)
            debug_log_path = os.path.join(self.logdir, debug_log_name)

        if enable_numpy is None:
            enable_numpy = ENABLE_NUMPY or 0

        env = dict(
            PORT=str(port), UPSTREAM=upstream_s, CREDS=creds,
            DEBUG=str(int(self.debug)), IOTRACE=str(int(self.iotrace)),
            DEBUG_LOG=debug_log_path, DUMP_LEN=str(DUMP_LEN),
            SSL_CERT=ssl_cert, SSL_CACERTS=SSL_CACERTS, LOCAL_OK=str(local_ok),
            SERVER=str(server), TIMEOUT=str(self.timeout), BUFLEN=str(BUFLEN),
            FORCE_PRIVATE=str(int(force_private)), QUIET=str(int(QUIET)),
            ENABLE_NUMPY=str(int(enable_numpy)),
            KEEPALIVE_SEC=str(KEEPALIVE_SEC),
            SHUTDOWN_SLEEP_SEC=str(SHUTDOWN_SLEEP_SEC),
            QUIRK_CONN_RESET=str(int(QUIRK_CONN_RESET)),
            GEVENT=str(int(GEVENT)), COVERAGE_PROCESS_START=self.coverage)
        proc = subprocess.Popen(
            args=[self.python] + sys.argv, env=env, bufsize=65536,
            stdin=open(os.devnull), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        self.out[idx] = ''
        proc.idx = idx
        self.procmap[idx] = dict(pid=proc.pid, debug_log=debug_log_name)
        self.procs.add(proc)

    def kill_all(self, idx=None, clear_all=True, timeout=5):
        def procs():
            if idx is not None:
                return sorted(p for p in self.procs if p.idx == idx)
            return sorted(self.procs)

        for proc in procs():
            try:
                proc.terminate()
            except OSError as err:
                print '!! Terminate process idx={idx} pid={pid}: {err}'.format(
                    idx=proc.idx, pid=proc.pid, err=err)
                self.out[proc.idx] = ''
                self.procs.discard(proc)

        start = time.time()
        while procs() and time.time() - start < timeout:
            for proc in procs():
                if proc.poll() is not None:
                    self.out[proc.idx] = proc.communicate()[0]
                    self.procs.discard(proc)
            time.sleep(0.5)

        for proc in procs():
            proc.kill()
            self.out[proc.idx] = proc.communicate()[0]

        if idx is None:
            self.procs = set()
            if FIXME_CA_PER_TEST:
                self.ca.clear_cache()
        if clear_all:
            self.clear_all()

    def comm(self, idx=None):
        self.kill_all(idx, clear_all=False)

    def request(self, port, ssl=False, path='echo', data='',
                via=None, check=None, repeat=1):
        self.resp = None
        self.resps = [None] * repeat
        self.curl_out = None
        self.req_count += 1

        scheme = 'https' if ssl else 'http'
        host = self.host
        verify = self.cacerts

        if isinstance(port, int):
            if port < 10:
                port += self.port
        else:
            host, _, port = port.partition(':')
            if not port:
                port = 443 if ssl else 80
            if host == 'ext':
                verify = False
                host = self.ext_host
            port = int(port)
            if port < 10 and self.ext_port:
                port += self.ext_port
        colon_port = '' if port == (443 if ssl else 80) else ':%d' % port
        url = '{scheme}://{host}{colon_port}/{path}'.format(
            scheme=scheme, host=host, colon_port=colon_port, path=path)

        if via:
            vhost = self.host
            if isinstance(via, int):
                vport = via
                if vport < 10:
                    vport += self.port
                via = 'http://{host}:{port:d}'.format(host=vhost, port=vport)
            elif isinstance(via, (list, tuple)):
                # (port,creds)
                vport = via[0]
                if vport < 10:
                    vport += self.port

                vcred = ''
                if via[1:] and via[1]:
                    vcred = '%s@' % via[1]
                via = 'http://{cred}{host}:{port:d}'.format(
                    cred=vcred, host=vhost, port=vport)
            elif isinstance(via, str) and via == 'ext':
                via = self.ext_via

        if data is 1:
            data = self.pattern
            if check is None:
                check = True

        if data:
            method = 'POST'
            dl = len(data)
        else:
            method = 'GET'
            data = None
            dl = 0

        if self.debug:
            print ('.. request #{count:<3d} {method:<5} {url:<30} dl={dl:<6d}'
                   ' via={via}'.format(count=self.req_count, method=method,
                                       url=url, dl=dl, via=via))

        if self.use_curl:
            args = ['curl', '-#', '-k', '-v']
            f_data = None
            if via:
                args += ['-x', via]

            if data:
                if re.match(r'^[0-9a-zA-Z_/,\.-:]{1,100}$', data):
                    args += ['-d', data]
                elif data == self.pattern:
                    args += ['-d', '@' + self.pattern_file.name]
                else:
                    f_data = tempfile.NamedTemporaryFile()
                    f_data.write(data)
                    f_data.flush()
                    args += ['-d', '@' + f_data.name]
            args += [url] * repeat

            start_time = time.time()
            try:
                self.curl_out = subprocess.check_output(
                    args, stdin=open(os.devnull), stderr=subprocess.STDOUT)
                retval = 0
            except subprocess.CalledProcessError as e:
                retval = e.returncode
                self.curl_out = e.output
            self.resp_time = time.time() - start_time

            if f_data:
                try:
                    f_data.close()
                    os.unlink(f_data.name)
                except Exception:
                    pass

            prog_rex = re.compile(r'\r#+\s+\d+\.\d%')
            code_rex = re.compile(r'< HTTP/\S+ (\d+)(?:[ \r\n]|$)')
            spec_rex = re.compile(r'([\r ]|[\*<>{}] |[<>]$)')
            next_rex = re.compile(r'(?:\r#+\s+\d+\.\d%)?\* ')

            code = [-1] * repeat
            body = [None] * repeat
            keepalive = [False] * repeat

            cur = 0
            for line in self.curl_out.split('\n'):
                if body[cur] is not None:
                    if next_rex.match(line):
                        cur += 1
                    else:
                        body[cur].append(line)
                        continue
                line = prog_rex.sub('', line)
                if code[cur] == -1:
                    mo = code_rex.match(line)
                    if mo:
                        code[cur] = int(mo.group(1))
                if line.startswith('* Re-using existing connection'):
                    keepalive[cur] = True
                if not spec_rex.match(line):
                    body[cur] = [line]

            class CurlResponse:
                pass

            for i in range(repeat):
                self.resps[i] = resp = CurlResponse()
                resp.status_code = code[i]
                resp.content = '\n'.join(body[i]) if body[i] else ''
                resp.keepalive = keepalive[i]

            if (retval != 0 or code[0] == -1) and DEBUG:
                print '%s\n****************' % dump(self.curl_out, max=None)
            if 0:
                print dump(self.resp.content, max=None)

        if self.use_requests:
            try:
                start_time = time.time()
                session = requests.Session()
                if via:
                    session.proxies = {scheme: via}
                func = session.post if data else session.get
                for cur in range(repeat):
                    resp = func(url, data=data, verify=verify)
                    _ = resp.content  # mark as used
                    resp.keepalive = (resp.headers.get('connection', '') ==
                                      'keep-alive')
                    self.resps[cur] = resp
            finally:
                self.resp_time = time.time() - start_time

        self.resp = self.resps[0]
        if self.debug:
            print '..    time %.2f' % self.resp_time

        if check:
            body = self.resp.content
            assert self.resp.status_code == 200, 'invalid status code'
            assert 'Request Line: %s ' % method in body, 'invalid method'
            assert 'Protocol: %s\n' % scheme in body, 'invalid protocol'
            if not self.pktfile and 50 < dl < ECHO_MEM_LIMIT:
                assert 'Test Pattern: OK\n' in body, 'invalid pattern'
            fmt_dl = locale.format('%d', dl, grouping=True)
            assert 'Body Length: %s\n' % fmt_dl in body, 'invalid length'

        return self.resp

    class SavedError(RuntimeError):
        pass

    def run_one_test(self, test_name):
        try:
            status = 'FAIL'
            self.clear_all()
            self.curr_name = test_name
            self.curr_mark = datetime.now().strftime('%Y%m%d_%H%M%S')
            if self.debug:
                print '.. begin: %s' % test_name
            self.kill_all()
            start_time = time.time()
            getattr(self, self.test_methods[test_name])()
            if len(self.loops) > self.progress_stride:
                print
            self.report_saved_errors()
            status = 'PASS'
        except AssertionError:
            traceback.print_exc()
            self.fail_count += 1
        except self.SavedError:
            self.fail_count += 1
        except (Exception, KeyboardInterrupt):
            print '!!!'
            traceback.print_exc(6)
            self.fail_count += 1
        finally:
            total_sec = time.time() - start_time
            if status == 'FAIL' or self.debug:
                self.comm()
                log_dir = self.logdir or os.getcwd()
                for port, out in sorted(self.out.items()):
                    details = self.procmap[port]['debug_log']
                    log_name = 'info-%s-%s-%d.log' % (self.curr_mark,
                                                      self.curr_name, port)
                    log_path = os.path.join(log_dir, log_name)
                    with open(log_path, 'w') as f:
                        f.write(out)
                    if status == 'FAIL':
                        if details:
                            print 'Process %s details in %s' % (port, details)
                        else:
                            print 'Process %s output  in %s' % (port, log_name)
                if self.curl_out is not None and self.iotrace:
                    curlout_name = 'curl-%s-%s.log' % (self.curr_mark,
                                                       self.curr_name)
                    curlout_path = os.path.join(log_dir, curlout_name)
                    with open(curlout_path, 'w') as f:
                        f.write(self.curl_out)
                    print '   Curl   output  in %s' % curlout_name
                resp = self.resp
                if resp is not None:
                    print ('Response (%d): %s' %
                           (resp.status_code, dump(resp.content, max=None)))
            print '>>>> Test %-12s %-5s (%d sec)' % (test_name, status,
                                                     total_sec)
            self.kill_all()
            self.clear_all()

    def clear_all(self):
        self.procs = set()
        self.out = {}
        self.procmap = {}
        self.resps = []
        self.resp = None
        self.curl_out = None
        self.err_list = []
        self.err_set = set()
        self.err_count = 0
        self.req_count = 0

    def save_error(self):
        if not self.soft_errors:
            raise
        etype, err, tb = sys.exc_info()
        print 'Exception %s.%s: %s' % (etype.__module__, etype.__name__,
                                       str(err))
        self.err_count += 1
        if str(err) not in self.err_set:
            self.err_list.append((etype, err, tb))
            self.err_set.add(str(err))

    def report_saved_errors(self, loops=None):
        def ending(n):
            return 's' if n != 1 else ''
        if not self.err_count:
            return
        if loops is None:
            loops = self.loops
        if not isinstance(loops, int):
            loops = len(loops)
        for etype, err, tb in self.err_list:
            err_eof = (isinstance(err, SSLError) and
                       ("SysCallError(-1, 'Unexpected EOF')" in str(err) or
                       'EOF occurred in violation of protocol' in str(err)))
            if not (FIXME_HIDE_EOF and err_eof):
                traceback.print_exception(etype, err, tb, limit=6)
        print ('Test %s: %d exception%s per %d loop%s'
               % (self.curr_name, self.err_count, ending(self.err_count),
                  loops, ending(loops)))
        raise self.SavedError

    def start_servers(self):
        if self.allow_plain:
            self.start(port=5, server=1)
        if self.allow_ssl and self.localhost_cert:
            self.start(port=6, server=1, ssl=1)

    def two_requests(self, loop=0, via=None, ext=False,
                     soft_errors=True, req_delay=None):
        soft_errors = soft_errors and self.soft_errors
        if req_delay is None:
            req_delay = self.req_delay
        if self.allow_plain:
            port = 'ext:5' if ext else 5
            if soft_errors:
                try:
                    self.request(port, data=1, via=via)
                except Exception:
                    self.save_error()
            else:
                self.request(port, data=1, via=via)
            safe_sleep(req_delay)
        if self.allow_ssl:
            port = 'ext:6' if ext else 6
            if soft_errors:
                try:
                    self.request(port, data=1, ssl=1, via=via)
                except Exception:
                    self.save_error()
            else:
                self.request(port, data=1, ssl=1, via=via)
            safe_sleep(req_delay)
        stride = self.progress_stride
        if not self.debug and loop >= stride and loop % stride == 0:
            print '%d..' % loop,
            sys.stdout.flush()

    def wait_startup(self):
        safe_sleep(2)

    def limit_loops(self, limit=3, when=True):
        if when and len(self.loops) > limit:
            print 'Slow test, loops=%d' % limit
            return range(limit)
        return self.loops

    def test_001_simple(self):
        self.start_servers()
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i)

    def test_01_chain1(self):
        self.start_servers()
        self.start(1)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=1)

    def test_02_chain2(self):
        # up: (port,proto,creds,path)
        # via: (port,creds)
        self.start_servers()
        self.start(1)
        self.start(2, up=1)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=2)
        self.report_saved_errors()
        self.comm()
        for port in (1, 2):
            assert '502 Bad Gateway' not in self.out[port]
            assert 'Connection reset by peer), not' not in self.out[port]

    def test_03_chain3(self):
        self.start_servers()
        self.start(1)
        self.start(2, up=1)
        self.start(3, up=2)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=3)

    def chain_neg(self, via):
        if self.allow_plain:
            resp = self.request(1, data='xxx', via=via, check=0,
                                path='_PRO_/_HERO_/xxx')
            assert resp.status_code == 501
            assert '501 Not Implemented (Invalid path)' in resp.content
            assert self.resp_time > AUTH_SLEEP
        if self.allow_plain:
            resp = self.request(5, data=1, via=via, check=0)
            assert resp.status_code == 503
            assert ('503 Service Unavailable (Connection refused)'
                    in resp.content)
        if self.allow_ssl and self.use_curl:
            resp = self.request(6, data=1, via=via, check=0, ssl=1)
            assert resp.status_code == 503
            assert ('Received HTTP code 503 from proxy after CONNECT'
                    in resp.content)
        if self.allow_ssl and self.use_requests:
            try:
                self.request(6, data=1, via=via, check=0, ssl=1)
            except ConnectionError as e:
                if ('Tunnel connection failed: '
                        '503 Service Unavailable' in str(e)):
                    pass
                else:
                    raise

    def test_04_chain1_neg(self):
        self.start(1)
        self.wait_startup()
        for i in self.loops:
            self.chain_neg(via=1)

    def test_05_chain2_neg(self):
        self.start(1)
        self.start(2, up=1)
        self.wait_startup()
        for i in self.loops:
            self.chain_neg(via=2)

    def test_06_chain3_neg(self):
        self.start(1)
        self.start(2, up=1)
        self.start(3, up=2)
        self.wait_startup()
        for i in self.loops:
            self.chain_neg(via=3)

    def test_10_creds1(self):
        self.start_servers()
        self.start(1, creds='u1:p1')
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=(1, 'u1:p1'))

    def creds1_neg(self, via, ssl):
        if not ssl and self.allow_plain:
            resp = self.request(5, data='abc', via=via, check=0)
            assert resp.status_code == 407
            assert '407 Proxy Authentication Required' in resp.content
            assert self.resp_time > AUTH_SLEEP
        if ssl and self.allow_ssl and self.use_curl:
            resp = self.request(6, data='abc', via=via, check=0, ssl=1)
            assert resp.status_code == 407
            assert ('Received HTTP code 407 from proxy after CONNECT'
                    in resp.content)
            assert self.resp_time > AUTH_SLEEP
        if ssl and self.allow_ssl and self.use_requests:
            try:
                self.request(6, data='abc', via=via, check=0, ssl=1)
            except ConnectionError as e:
                if ('Tunnel connection failed: '
                        '407 Proxy Authentication Required' in str(e)):
                    pass
                else:
                    raise
                assert self.resp_time > AUTH_SLEEP

    def test_11_creds1_neg(self):
        self.start_servers()
        self.start(1, creds='u1:p1')
        self.wait_startup()
        for i in self.limit_loops():
            self.creds1_neg(via=1, ssl=0)
            self.creds1_neg(via=(1, 'u2:p2'), ssl=0)
            self.creds1_neg(via=1, ssl=1)
            self.creds1_neg(via=(1, 'u2:p2'), ssl=1)

    def test_12_creds2(self):
        self.start_servers()
        self.start(1, creds='u1:p1')
        self.start(2, up=(1, '', 'u1:p1'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=2)

    def creds2_neg(self, via):
        if self.allow_plain:
            resp = self.request(5, data='abc', via=via, check=0)
            assert resp.status_code == 407
            assert ('407 Proxy Authentication Required'
                    ' (Gateway connection refused)') in resp.content
            assert self.resp_time > AUTH_SLEEP
        if self.allow_ssl and self.use_curl:
            resp = self.request(6, data='abc', via=via, check=0, ssl=1)
            assert resp.status_code == 407
            assert ('Received HTTP code 407 from proxy after CONNECT'
                    in resp.content)
            assert self.resp_time > AUTH_SLEEP
        if self.allow_ssl and self.use_requests:
            try:
                self.request(6, data='abc', via=via, check=0, ssl=1)
            except ConnectionError as e:
                if ('Tunnel connection failed: '
                        '407 Proxy Authentication Required' in str(e)):
                    pass
                else:
                    raise
            assert self.resp_time > AUTH_SLEEP

    def test_13_creds2_neg(self):
        self.start_servers()
        self.start(1, creds='u1:p1')
        self.start(2, up=(1, '', 'u2:p2'))
        self.wait_startup()
        for i in self.limit_loops():
            self.creds2_neg(via=2)

    def test_14_creds3(self):
        self.start_servers()
        self.start(1, creds='u1:p1')
        self.start(2, creds='u2:p2', up=(1, '', 'u1:p1'))
        self.start(3, up=(2, '', 'u2:p2'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=3)

    def test_15_creds3_neg(self):
        self.start_servers()
        self.start(1, creds='u1:p1')
        self.start(2, creds='u2:p2', up=(1, '', 'n0:p0'))
        self.start(3, up=(2, '', 'u2:p2'))
        self.wait_startup()
        for i in self.limit_loops():
            self.creds2_neg(via=3)

    def test_21_ssl_2(self):
        # up: (port,proto,creds,path)
        # via: (port,creds)
        self.start_servers()
        self.start(1, ssl=1)
        self.start(2, up=(1, 'pros'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=2)

    def test_22_ssl_3(self):
        self.start_servers()
        self.start(1, ssl=1)
        self.start(2, ssl=1, up=(1, 'pros'))
        self.start(3, up=(2, 'pros'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=3)

    def ssl1_neg(self, port, ssl):
        if self.use_curl:
            resp = self.request(port, ssl=ssl, data=1, via=1, check=0)
            assert resp.status_code == -1
            assert 'Connection reset by peer' in resp.content
        if self.use_requests:
            try:
                self.request(port, ssl=ssl, data=1, via=1, check=0)
                raise RuntimeError('Requests must fail here')
            except ConnectionError as e:
                assert 'Cannot connect to proxy' in str(e)

    def test_23_ssl_1_neg(self):
        # up: (port,proto,creds,path)
        # via: (port,creds)
        self.start_servers()
        self.start(1, ssl=1)
        self.wait_startup()
        for i in self.loops:
            if self.allow_plain:
                self.ssl1_neg(port=5, ssl=0)
            if self.allow_ssl:
                self.ssl1_neg(port=6, ssl=1)

    def ssl2_neg(self, via):
        if self.allow_plain:
            resp = self.request(5, data=1, via=via, check=0)
            assert resp.status_code == 502
            assert '502 Bad Gateway (Connection reset by peer)' in resp.content
        if self.allow_ssl and self.use_curl:
            resp = self.request(6, data=1, via=via, check=0, ssl=1)
            assert resp.status_code == 502
            assert 'Received HTTP code 502 from proxy' in resp.content
        if self.allow_ssl and self.use_requests:
            try:
                self.request(6, ssl=1, data=1, via=via, check=0)
                raise RuntimeError('Requests must fail here')
            except ConnectionError as e:
                assert 'Tunnel connection failed: 502 Bad Gateway' in str(e)

    def test_24_ssl_2_neg(self):
        # up: (port,proto,creds,path)
        # via: (port,creds)
        self.start_servers()
        self.start(1, ssl=1)
        self.start(2, up=(1, 'pro'))
        self.wait_startup()
        for i in self.loops:
            self.ssl2_neg(via=2)

    def test_25_ssl_3_neg(self):
        self.start_servers()
        self.start(1, ssl=1)
        self.start(2, ssl=1, up=(1, 'pro'))
        self.start(3, up=(2, 'pros'))
        self.wait_startup()
        for i in self.loops:
            self.ssl2_neg(via=3)

    def test_31_private1(self):
        self.start_servers()
        self.start(1, creds='n1:p1', enable_numpy=1)
        self.start(2, up=(1, '', 'n1:p1', 'private'), enable_numpy=1)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=2)

    def test_32_private1_neg(self):
        self.start_servers()
        self.start(1, creds='n1:p1', enable_numpy=1)
        self.start(2, up=(1, '', 'n2:p2', 'private'), enable_numpy=1)
        self.wait_startup()
        for i in self.limit_loops():
            self.creds2_neg(via=2)

    def test_33_private2(self):
        self.start_servers()
        self.start(1, creds='n1:p1', enable_numpy=1)
        self.start(2, creds='n2:p2', up=(1, '', 'n1:p1', 'private'),
                   enable_numpy=1)
        self.start(3, up=(2, '', 'n2:p2', 'private'), enable_numpy=1)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=3)

    def test_34_private2_neg(self):
        self.start_servers()
        self.start(1, creds='n1:p1', enable_numpy=1)
        self.start(2, creds='n2:p2', up=(1, '', 'n0:p0', 'private'),
                   enable_numpy=1)
        self.start(3, up=(2, '', 'n2:p2', 'private'), enable_numpy=1)
        self.wait_startup()
        for i in self.limit_loops():
            self.creds2_neg(via=3)

    def test_35_private_force(self):
        self.start_servers()
        self.start(1, creds='n1:p1', force_private=1, enable_numpy=1)
        self.start(2, up=(1, '', 'n1:p1', 'private'), enable_numpy=1)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=2)

    def private_force_neg1(self, via, ssl):
        if not ssl and self.allow_plain:
            resp = self.request(5, data='abc', via=via, check=0)
            assert resp.status_code == 501
            assert '501 Not Implemented (Private only)' in resp.content
            assert self.resp_time > AUTH_SLEEP
        if ssl and self.allow_ssl and self.use_curl:
            resp = self.request(6, data='abc', via=via, check=0, ssl=1)
            assert resp.status_code == 501
            assert ('Received HTTP code 501 from proxy after CONNECT'
                    in resp.content)
            assert self.resp_time > AUTH_SLEEP
        if ssl and self.allow_ssl and self.use_requests:
            try:
                self.request(6, data='abc', via=via, check=0, ssl=1)
            except ConnectionError as e:
                if 'Tunnel connection failed: 501 Not Implemented' in str(e):
                    pass
                else:
                    raise
                assert self.resp_time > AUTH_SLEEP

    def test_36_private_force_neg1(self):
        self.start_servers()
        self.start(1, force_private=1, enable_numpy=1)
        self.wait_startup()
        for i in self.limit_loops():
            self.private_force_neg1(via=1, ssl=0)
            self.private_force_neg1(via=1, ssl=1)

    def test_37_private_force_neg2(self):
        self.start_servers()
        self.start(1, creds='n1:p1', force_private=1, enable_numpy=1)
        self.start(2, up=(1, '', 'n1:p1', ''), enable_numpy=1)
        self.wait_startup()
        for i in self.loops:
            if self.allow_plain and self.use_curl:
                resp = self.request(5, data=1, via=2, check=0)
                assert resp.status_code == -1
                assert ('Empty reply from server' in resp.content or
                        'Connection reset by peer' in resp.content)
            if self.allow_ssl and self.use_curl:
                resp = self.request(6, data=1, via=2, check=0, ssl=1)
                assert resp.status_code == -1
                assert 'Proxy CONNECT aborted' in resp.content
            if self.allow_plain and self.use_requests:
                try:
                    resp = self.request(5, ssl=0, data=1, via=2, check=0)
                    assert resp.status_code == 502
                    assert ('502 Bad Gateway (Connection reset by peer)'
                            in resp.content)
                except ConnectionError as e:
                    assert 'Connection aborted' in str(e)
            if self.allow_ssl and self.use_requests:
                try:
                    self.request(6, ssl=1, data=1, via=2, check=0)
                    raise RuntimeError('Requests must fail here')
                except ConnectionError as e:
                    assert 'Connection aborted' in str(e)
        self.comm()
        assert 'invalid message' in (self.out[1] + self.out[2])

    def test_41_keepalive1(self):
        for ssl in (0, 1):
            if (ssl and self.allow_ssl) or (not ssl and self.allow_plain):
                repeat = 3
                self.request('httpbin.org', path='get', data=None,
                             via=None, ssl=ssl, repeat=repeat)
                assert self.resps[0].status_code == 200
                for i in range(1, repeat):
                    assert self.resps[i].status_code == 200
                    assert self.resps[i].keepalive is True

    def upstream_neg(self, via):
        if self.allow_plain:
            resp = self.request(5, data=1, via=via, check=0)
            assert resp.status_code == 504
            assert '504 Gateway Timeout (Connection refused)' in resp.content
        if self.allow_ssl and self.use_curl:
            resp = self.request(6, data=1, via=via, check=0, ssl=1)
            assert resp.status_code == 504
            assert 'Received HTTP code 504 from proxy' in resp.content
        if self.allow_ssl and self.use_requests:
            try:
                self.request(6, ssl=1, data=1, via=via, check=0)
                raise RuntimeError('Requests must fail here')
            except ConnectionError as e:
                if 'connection failed: 504 Gateway Timeout' in str(e):
                    pass
                else:
                    raise

    def test_51_upstream1(self):
        self.start_servers()
        self.start(1)
        self.start(4, up=1)
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=4)
        self.comm(1)
        for i in self.limit_loops():
            self.upstream_neg(via=4)

    def test_53_upstream3(self):
        self.start_servers()
        self.start(1)
        self.start(2)
        self.start(3)
        self.start(4, up=[1, 2, 3])
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=4)
        self.comm(1)
        for i in self.loops:
            self.two_requests(loop=i, via=4)
        self.comm(2)
        for i in self.loops:
            self.two_requests(loop=i, via=4)
        self.comm(3)
        for i in self.limit_loops():
            self.upstream_neg(via=4)
        self.comm(4)
        switch_msg = 'switch upstream to %s:%%d' % self.host
        assert switch_msg % (self.port + 2) in self.out[4]
        assert switch_msg % (self.port + 3) in self.out[4]

    def test_91_hero_simple(self):
        self.start(1, up=('ext', 'pro', '', 'lowbuf'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=1, ext=True)

    def test_92_hero_ssl(self):
        self.start(1, up=('ext', 'pros', '', 'lowbuf'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=1, ext=True)

    def test_93_hero_private(self):
        self.start(1, up=('ext', 'pro', '', 'private', 'lowbuf'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=1, ext=True)

    def test_94_hero_ssl_private(self):
        self.start(1, up=('ext', 'pros', '', 'private', 'lowbuf'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=1, ext=True)

    def test_95_hero_max(self):
        self.start(1, up=('ext', 'pros', '', 'private', 'lowbuf'))
        self.wait_startup()
        for i in self.loops:
            self.two_requests(loop=i, via=1, ext=True)

    def test_96_hero_ext(self):
        for i in self.loops:
            self.two_requests(loop=i, via='ext', ext=True)


def main():
    locale.setlocale(locale.LC_ALL, ('en_US', 'UTF-8'))

    if TEST:
        test_list, _, arg_line = TEST.partition(':')
        test_args = dict(debug=DEBUG, iotrace=IOTRACE)
        for token in arg_line.strip().split(','):
            if token.strip():
                name, _, val = token.strip().partition('=')
                test_args[name] = int(val) if re.match(r'-?\d+$', val) else val
        SelfTests(test_list, **test_args)
    elif PROFILER and PROFILER != '-line_profiler':
        import cProfile
        psort = (PROFILER[1:] if PROFILER[0] == '-' else None) or -1
        pfile = None if pfile.startswith('-') else pfile
        cProfile.run('start_server()', pfile, psort)
    else:
        start_server()


if __name__ == '__main__':
    main()
