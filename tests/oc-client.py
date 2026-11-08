#!/usr/bin/env python3
#
# Copyright (C) 2026 Nikos Mavrogiannopoulos
# Copyright (C) 2026 Pierre-Yves Le Borgne
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""A scriptable AnyConnect client for the ocserv tests.

openconnect is the client for everything a conforming client does. This
tool is for what openconnect cannot be asked to do or does not show: it
reports what the server offered, and sends what it is told to send, even
when a conforming client would refuse to, so that a test checks that the
server enforces a rule instead of relying on the client to.

Every command prints what it observed, one item per line, to standard
output or to the file given with --output, and exits with:

  0  the server did what the command checks for (e.g. accepted a login)
  1  the server refused (e.g. rejected a login)
  2  anything else (no connection, an unexpected response), with the
     reason on stderr, so that a broken exchange is never mistaken for
     a refusal

Every message exchanged with the server is written to standard error or
to the file given with --log, so that a failing test can show what was sent
and what came back.

To add a command, write a cmd_<name>(server, args) function returning one
of the exit codes above and register it with @command.
"""

import argparse
import base64
import html
import http.client
import ipaddress
import os
import re
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlencode
from xml.sax.saxutils import escape

OK = 0
REFUSED = 1
ERROR = 2

CLIENT_VERSION = "4.8.03036"
# The User-Agent of each class of client ocserv tells apart; it acts on the
# class, not on the exact string
CLIENTS = {
    "anyconnect": "AnyConnect Darwin_i386 " + CLIENT_VERSION,
    "openconnect": "Open AnyConnect VPN Agent v9.12",
    "svc": "Cisco SVC IPPhone Client v1.0",
    "none": None,
}
TIMEOUT = 10


class ProtocolError(Exception):
    """The server answered in a way the command does not expect."""


# ---------------------------------------------------------------------------
# Transport: one TLS connection to a virtual host
# ---------------------------------------------------------------------------


class _VhostConnection(http.client.HTTPSConnection):
    """Connects to an address but names the virtual host in SNI and in the
    Host header, like curl --resolve. The tests' server certificates are
    not verified; a client certificate is presented when one is given."""

    def __init__(self, address, port, vhost, cert=None, key=None):
        self.tls = ssl.create_default_context()
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE
        if cert is not None:
            self.tls.load_cert_chain(cert, key)
        super().__init__(vhost, port, timeout=TIMEOUT, context=self.tls)
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port),
                                        self.timeout)
        self.sock = self.tls.wrap_socket(sock, server_hostname=self.host)


class Reply:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body
        self.set_cookies = headers.get_all("Set-Cookie") or []


class Server:
    """Sends requests to one virtual host as the client named by its
    User-Agent, and keeps the cookies the server sets, as a client must to
    continue a login."""

    def __init__(self, address, port, vhost, user_agent, output, log,
                 cert=None, key=None):
        self.conn = _VhostConnection(address, port, vhost, cert, key)
        self.user_agent = user_agent
        self.cookies = {}
        self.output = output
        self.log = log

    def report(self, line):
        """Prints one item of what the command observed."""
        print(line, file=self.output)

    def trace(self, direction, first_line, body=""):
        """Logs one message of the exchange."""
        print("%s %s" % (direction, first_line), file=self.log)
        for line in body.splitlines():
            print("%s   %s" % (direction, line), file=self.log)

    def post_xml(self, body, path="/"):
        """Posts an AnyConnect aggregate authentication message."""
        return self.request("POST", path, body,
                            {"X-Transcend-Version": "1",
                             "X-Aggregate-Auth": "1"})

    def post_form(self, fields, path):
        """Posts HTML form fields, as the Cisco SVC client does."""
        return self.request(
            "POST", path, urlencode(fields),
            {"Content-Type": "application/x-www-form-urlencoded"})

    def request(self, method, path, body=None, headers=None):
        headers = dict(headers or {})
        if self.user_agent and "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
        if self.cookies:
            headers["Cookie"] = "; ".join(
                "%s=%s" % c for c in self.cookies.items())
        self.trace(">", "%s %s" % (method, path), body or "")
        self.conn.request(method, path,
                          None if body is None else body.encode(), headers)
        resp = self.conn.getresponse()
        reply = Reply(resp.status, resp.msg,
                      resp.read().decode(errors="replace"))
        self.trace("<", "HTTP %d %s" % (resp.status, resp.reason),
                   "".join("Set-Cookie: %s\n" % c for c in reply.set_cookies)
                   + reply.body)
        for cookie in reply.set_cookies:
            self._keep(cookie)
        return reply

    def _keep(self, set_cookie):
        name, _, value = set_cookie.split(";", 1)[0].partition("=")
        if value:
            self.cookies[name.strip()] = value
        else:
            self.cookies.pop(name.strip(), None)


# ---------------------------------------------------------------------------
# AnyConnect messages (aggregate authentication, XML)
# ---------------------------------------------------------------------------


def config_auth(msg_type, elements):
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<config-auth client="vpn" type="%s" '
            'aggregate-auth-version="2">\n'
            '<version who="vpn">%s</version>\n'
            '%s</config-auth>\n') % (msg_type, CLIENT_VERSION,
                                     "".join(e + "\n" for e in elements))


def element(name, value):
    return "<%s>%s</%s>" % (name, escape(value), name)


def group_select(group):
    return [] if group is None else [element("group-select", group)]


def init_request(group=None):
    """The message that starts a login; AnyConnect proposes the group it
    used last."""
    return config_auth("init", group_select(group))


def auth_reply(username, password, group=None):
    """The answer to the login form. The username and password go
    together: the server reads the password from the same request as the
    username."""
    return config_auth("auth-reply",
                       ["<auth>" + element("username", username)
                        + element("password", password) + "</auth>"]
                       + group_select(group))


_GROUP_LIST = re.compile(r'<select name="group_list"[^>]*>(.*?)</select>',
                         re.S)
_OPTION = re.compile(r'<option(?: value="([^"]*)")?>([^<]*)</option>')


def offered_groups(form):
    """The (value, label) of each group in the login form, in the order
    offered, or None if the form has no group list."""
    match = _GROUP_LIST.search(form)
    if match is None:
        return None
    groups = []
    for value, label in _OPTION.findall(match.group(1)):
        label = html.unescape(label)
        groups.append((html.unescape(value) if value else label, label))
    return groups


def asks_for_password(form):
    return 'type="password"' in form


_MESSAGE = re.compile(r"<message>(.*?)</message>", re.S)
_AUTH_ID = re.compile(r'<auth id="([^"]*)"')


def messages(body):
    return [html.unescape(m) for m in _MESSAGE.findall(body)]


def auth_ids(body):
    """The id of each <auth> element: "main" for a form, "success" for a
    completed login."""
    return _AUTH_ID.findall(body)


# ---------------------------------------------------------------------------
# CSTP tunnel: IP packets in CSTP records, sent directly over the TLS
# connection once a CONNECT has opened the tunnel
# ---------------------------------------------------------------------------

AC_PKT_DATA = 0
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def echo_request(src, dst, ident, seq):
    icmp = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    icmp += b"cstp-burst %d" % seq
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), seq, 0, 64,
                     socket.IPPROTO_ICMP, 0, src.packed, dst.packed)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + icmp


def echo_reply_seq(packet, src, dst, ident):
    """The sequence number of an echo reply from src to dst, or None."""
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    hlen = (packet[0] & 0x0F) * 4
    if (packet[9] != socket.IPPROTO_ICMP or packet[12:16] != src.packed
            or packet[16:20] != dst.packed or len(packet) < hlen + 8):
        return None
    icmp_type, _, _, reply_ident, seq = struct.unpack(
        "!BBHHH", packet[hlen:hlen + 8])
    if icmp_type != ICMP_ECHO_REPLY or reply_ident != ident:
        return None
    return seq


def cstp_record(payload):
    return b"STF\x01" + struct.pack("!HBB", len(payload), AC_PKT_DATA,
                                    0) + payload


class Tunnel:
    """A tunnel opened with a CONNECT that carries a session cookie, over
    which IPv4 packets travel in CSTP records."""

    def __init__(self, server, cookie):
        self.server = server
        server.conn.connect()
        self.tls = server.conn.sock
        request = ("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
                   "Host: %s\r\n"
                   "User-Agent: %s\r\n"
                   "Cookie: webvpn=%s\r\n"
                   "X-CSTP-Version: 1\r\n"
                   "X-CSTP-Hostname: cstp-burst\r\n"
                   "X-CSTP-Address-Type: IPv4\r\n"
                   "\r\n" % (server.conn.host, server.user_agent, cookie))
        first, _, headers = request.partition("\r\n")
        server.trace(">", first, headers.replace("\r\n", "\n"))
        self.tls.sendall(request.encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            data = self.tls.recv(4096)
            if not data:
                raise ProtocolError("connection closed before the end of "
                                    "the CONNECT reply: %r" % self.buf)
            self.buf += data
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        server.trace("<", lines[0], "\n".join(lines[1:]))
        if not lines[0].startswith("HTTP/1.1 200"):
            raise ProtocolError("CONNECT refused: %s" % lines[0])
        self.address = None
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() != "x-cstp-address":
                continue
            try:
                self.address = ipaddress.IPv4Address(value.strip())
                break
            except ValueError:
                pass
        if self.address is None:
            raise ProtocolError("no IPv4 X-CSTP-Address in the CONNECT "
                                "reply")

    def send(self, records):
        self.server.trace(">", "%d CSTP record(s)" % len(records))
        # one sendall() per record: each goes out in its own TLS record
        for record in records:
            self.tls.sendall(record)

    def echo_requests(self, target, ident, seqs):
        return [cstp_record(echo_request(self.address, target, ident, s))
                for s in seqs]

    def receive(self, timeout, handle):
        """Call handle(type, payload) for each CSTP packet received, until
        it returns True ("done"), the server closes the connection
        ("closed") or timeout seconds pass ("timeout")."""
        deadline = time.monotonic() + timeout
        while True:
            while len(self.buf) >= 8:
                if self.buf[:4] != b"STF\x01":
                    raise ProtocolError("unexpected data from the server: "
                                        "%r" % self.buf[:16])
                length = struct.unpack("!H", self.buf[4:6])[0]
                if len(self.buf) < 8 + length:
                    break
                packet_type = self.buf[6]
                payload = self.buf[8:8 + length]
                self.buf = self.buf[8 + length:]
                if handle(packet_type, payload):
                    return "done"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timeout"
            self.tls.settimeout(remaining)
            try:
                data = self.tls.recv(16384)
            except socket.timeout:
                return "timeout"
            except (ConnectionError, ssl.SSLError):
                return "closed"
            if not data:
                return "closed"
            self.buf += data


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

COMMANDS = {}


def arg(*flags, **options):
    return flags, options


def command(name, *arguments):
    """Registers a command; each argument is an arg(...) passed on to
    argparse. The function's docstring is the command's help, its first
    line the summary in the list of commands."""
    def register(func):
        COMMANDS[name] = (func, arguments)
        return func
    return register


@command("groups",
         arg("--group", help="group to propose, as a client does with the "
             "group it used last"))
def cmd_groups(server, args):
    """Print the groups the login form offers.

    One 'value<TAB>label' line per group, in the order offered."""
    reply = server.post_xml(init_request(group=args.group))
    if reply.status != 200:
        raise ProtocolError("expected the login form, got HTTP %d"
                            % reply.status)
    groups = offered_groups(reply.body)
    if groups is None:
        raise ProtocolError("the login form has no group list:\n"
                            + reply.body)
    for value, label in groups:
        server.report("%s\t%s" % (value, label))
    return OK


@command("init",
         arg("--group", help="group to propose, sent as given even if the "
             "server does not list it"))
def cmd_init(server, args):
    """Start a login and print what the server answered.

    One item per line, headers as the server sent them:
      Content-Type: VALUE
      Message: TEXT                       each message of the form
      Group: value="VALUE" label="LABEL"  each group, in the order offered
      Auth: ID                            each <auth> id ("success" for a
                                          completed login)
      Set-Cookie: HEADER                  each Set-Cookie header"""
    reply = server.post_xml(init_request(group=args.group))
    if reply.status != 200:
        raise ProtocolError("expected an answer to the init message, got "
                            "HTTP %d" % reply.status)
    server.report("Content-Type: %s" % reply.headers.get("Content-Type", ""))
    for text in messages(reply.body):
        server.report("Message: %s" % text)
    for value, label in offered_groups(reply.body) or []:
        server.report('Group: value="%s" label="%s"' % (value, label))
    for auth_id in auth_ids(reply.body):
        server.report("Auth: %s" % auth_id)
    report_cookies(server, reply)
    return OK


def report_cookies(server, reply):
    for cookie in reply.set_cookies:
        server.report("Set-Cookie: %s" % cookie)


@command("svc",
         arg("--method", choices=["GET", "POST"], default="POST"),
         arg("--user", help="username to post"),
         arg("--password", help="password to post"))
def cmd_svc(server, args):
    """Send a request to /svc as a Cisco SVC IP phone does.

    Always presents the Cisco SVC client's User-Agent. The username and
    password, those given, are posted as HTML form fields. Prints each
    Set-Cookie header as 'Set-Cookie: HEADER'."""
    fields = {name: value for name, value in
              (("username", args.user), ("password", args.password))
              if value is not None}
    headers = {"User-Agent": CLIENTS["svc"]}
    body = None
    if fields:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode(fields)
    reply = server.request(args.method, "/svc", body, headers)
    report_cookies(server, reply)
    return OK


@command("login",
         arg("--group", help="group to propose, sent as given even if the "
             "form does not offer it"),
         arg("--user", required=True),
         arg("--password", required=True))
def cmd_login(server, args):
    """Log in with a username and password.

    Succeeds if the server issues a session cookie, refuses if it rejects
    the login."""
    reply = server.post_xml(init_request(group=args.group))
    if reply.status != 200 or not asks_for_password(reply.body):
        raise ProtocolError("expected the login form, got HTTP %d"
                            % reply.status)
    reply = server.post_xml(auth_reply(args.user, args.password, args.group))
    if reply.status == 401:
        server.report("login rejected")
        return REFUSED
    if reply.status == 200 and "webvpn" in server.cookies:
        server.report("session cookie issued")
        return OK
    raise ProtocolError("expected a session cookie or a rejection, got "
                        "HTTP %d:\n%s" % (reply.status, reply.body))


@command("username-only",
         arg("--user", required=True))
def cmd_username_only(server, args):
    """Post a username without its password.

    This is what a client that abandons a login after giving its username
    sends: the server starts authenticating the user, then finds no
    password. Succeeds if the server issues a session cookie anyway,
    refuses if it rejects the login."""
    reply = server.post_form({"username": args.user}, "/auth")
    return login_result(server, reply)


# A captured, generic GSSAPI/SPNEGO NTLMSSP Type1 (negotiate) token. Type1
# carries only capability flags, no credentials, so it is not tied to any
# particular username/password and is safe to reuse as a static fixture.
NTLMSSP_TYPE1 = (
    "YEgGBisGAQUFAqA+MDygDjAMBgorBgEEAYI3AgIKoioEKE5UTE1TU1AAAQAAABeCCOIA"
    "AAAAAAAAAAAAAAAAAAAABgIAAAAAAA8="
)


@command("negotiate-fallback",
         arg("--user", required=True),
         arg("--password", required=True))
def cmd_negotiate_fallback(server, args):
    """Fail GSSAPI, then log in with a password on the same connection.

    Sends an NTLMSSP Type1 token, which the server answers with a
    challenge, then the same token again as the continuation, which
    fails, and finally the username and password, all over one connection
    and therefore to one worker. Succeeds if the password login completes,
    refuses if it is rejected."""
    negotiate = {"Authorization": "Negotiate " + NTLMSSP_TYPE1,
                 "X-Support-HTTP-Auth": "1"}
    server.request("GET", "/", headers=negotiate)
    server.request("GET", "/", headers=negotiate)
    reply = server.post_form({"username": args.user,
                              "password": args.password}, "/auth")
    return login_result(server, reply)


@command("oversized",
         arg("--method", choices=["GET", "POST"], default="POST"),
         arg("--path", default="/"),
         arg("--body-size", type=int, default=0,
             help="send a body of this many zero bytes"),
         arg("--headers", type=int, default=0,
             help="add this many 1 KiB X-Test-N headers"),
         arg("--cookie", metavar="NAME:BYTES",
             help="send cookie NAME with the base64 encoding of BYTES "
             "zero bytes as its value"))
def cmd_oversized(server, args):
    """Send a request with an oversized part and report the outcome.

    Prints 'Status: CODE' if the server answered. Succeeds if it
    answered with any status but 413 or 431. Refuses if it answered 413
    or 431, or closed the connection without answering after the TLS
    handshake, even while the request was still being sent: this is how
    ocserv refuses a request over its limits, and also how a worker that
    crashed looks, so a test must check the server's log for crashes."""
    headers = {}
    for i in range(args.headers):
        headers["X-Test-%d" % i] = "A" * 1024
    if args.cookie:
        name, _, size = args.cookie.partition(":")
        value = base64.b64encode(bytes(int(size))).decode()
        headers["Cookie"] = "%s=%s" % (name, value)
    body = None
    if args.method == "POST":
        body = "\0" * args.body_size
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    server.conn.connect()
    try:
        reply = server.request(args.method, args.path, body, headers)
    except (ConnectionError, ssl.SSLError) as e:
        server.report("closed without a response")
        server.trace("<", "connection closed: %s" % e)
        return REFUSED
    server.report("Status: %d" % reply.status)
    return REFUSED if reply.status in (413, 431) else OK


TUNNEL_ARGS = (
    arg("--cookie", required=True,
        help="session cookie (webvpn) to open the tunnel with"),
    arg("--target", type=ipaddress.IPv4Address, required=True,
        help="the server's address in the tunnel"),
    arg("--timeout", type=float, default=10,
        help="seconds to wait for the server"))


@command("cstp-echo",
         *TUNNEL_ARGS,
         arg("--count", type=int, default=20,
             help="echo requests sent back to back"))
def cmd_cstp_echo(server, args):
    """Ping the server through the tunnel, alone and back to back.

    Sends one ICMP echo request in a CSTP record, then COUNT of them back
    to back, each record in its own TLS record. The worker reads the one
    record there is, and must then go back to its event loop to forward
    the reply from the TUN device. Succeeds if every request is answered
    within the timeout, refuses if one is not."""
    tun = Tunnel(server, args.cookie)
    ident = os.getpid() & 0xFFFF
    replies = set()

    def answered(seqs, what):
        def handle(packet_type, payload):
            if packet_type == AC_PKT_DATA:
                seq = echo_reply_seq(payload, args.target, tun.address,
                                     ident)
                if seq is not None:
                    replies.add(seq)
            return replies.issuperset(seqs)

        result = tun.receive(args.timeout, handle)
        if result != "done":
            server.report("%s: no reply to echo request(s) %s "
                          "(connection %s)"
                          % (what, sorted(set(seqs) - replies), result))
            return False
        server.report("%s answered" % what)
        return True

    tun.send(tun.echo_requests(args.target, ident, [0]))
    if not answered([0], "a single echo request"):
        return REFUSED
    burst = range(1, args.count + 1)
    tun.send(tun.echo_requests(args.target, ident, burst))
    if not answered(burst, "%d echo requests sent back to back"
                    % args.count):
        return REFUSED
    return OK


@command("cstp-malformed", *TUNNEL_ARGS)
def cmd_cstp_malformed(server, args):
    """Send echo requests, then a record with a malformed CSTP header.

    Succeeds if the server closes the connection within the timeout,
    refuses if it keeps it open."""
    tun = Tunnel(server, args.cookie)
    bad_header = b"XTF\x01" + struct.pack("!HBB", 0, AC_PKT_DATA, 0)
    tun.send(tun.echo_requests(args.target, os.getpid() & 0xFFFF, range(3))
             + [bad_header])
    if tun.receive(args.timeout, lambda packet_type, payload: False) \
            == "closed":
        server.report("the server closed the connection after a malformed "
                      "record")
        return OK
    server.report("the connection was still open %g s after a record with "
                  "a malformed CSTP header" % args.timeout)
    return REFUSED


def login_result(server, reply):
    """The exit code for the reply that ends a login."""
    if reply.status == 401:
        server.report("login rejected")
        return REFUSED
    if reply.status == 200 and 'auth id="success"' in reply.body:
        server.report("login completed")
        return OK
    raise ProtocolError("expected a completed or a rejected login, got "
                        "HTTP %d:\n%s" % (reply.status, reply.body))


# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--address", required=True,
                        help="address the server listens on")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host",
                        help="virtual host named in SNI and the Host header "
                        "(default: the address)")
    parser.add_argument("--client", choices=CLIENTS, default="anyconnect",
                        help="class of client to present as, by its "
                        "User-Agent; none sends no User-Agent (default: "
                        "%(default)s)")
    parser.add_argument("--user-agent",
                        help="exact User-Agent to send instead of the "
                        "--client one")
    parser.add_argument("--cert", help="client certificate file")
    parser.add_argument("--key", help="client certificate's key file")
    parser.add_argument("--output", type=argparse.FileType("w"),
                        default=sys.stdout,
                        help="file to print what was observed to "
                        "(default: standard output)")
    parser.add_argument("--log", type=argparse.FileType("w"),
                        default=sys.stderr,
                        help="file to log the exchange with the server to "
                        "(default: standard error)")
    commands = parser.add_subparsers(dest="command")
    commands.required = True
    for name, (func, arguments) in COMMANDS.items():
        sub = commands.add_parser(
            name, help=func.__doc__.split("\n")[0], description=func.__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        for flags, options in arguments:
            sub.add_argument(*flags, **options)
        sub.set_defaults(func=func)
    args = parser.parse_args()
    user_agent = args.user_agent
    if user_agent is None:
        user_agent = CLIENTS[args.client]

    try:
        server = Server(args.address, args.port, args.host or args.address,
                        user_agent, args.output, args.log, args.cert,
                        args.key)
        return args.func(server, args)
    except (ProtocolError, OSError, http.client.HTTPException) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        if args.log is not sys.stderr:
            print("ERROR: %s" % e, file=args.log)
        return ERROR


if __name__ == "__main__":
    sys.exit(main())
