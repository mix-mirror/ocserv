#!/usr/bin/env python3
#
# Copyright (C) 2026 Nikos Mavrogiannopoulos
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
import html
import http.client
import re
import socket
import ssl
import sys
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
