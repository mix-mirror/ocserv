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
from xml.sax.saxutils import escape

OK = 0
REFUSED = 1
ERROR = 2

CLIENT_VERSION = "4.8.03036"
TIMEOUT = 10


class ProtocolError(Exception):
    """The server answered in a way the command does not expect."""


# ---------------------------------------------------------------------------
# Transport: one TLS connection to a virtual host
# ---------------------------------------------------------------------------


class _VhostConnection(http.client.HTTPSConnection):
    """Connects to an address but names the virtual host in SNI and in the
    Host header, like curl --resolve. The tests' server certificates are
    not verified."""

    def __init__(self, address, port, vhost):
        self.tls = ssl.create_default_context()
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE
        super().__init__(vhost, port, timeout=TIMEOUT, context=self.tls)
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port),
                                        self.timeout)
        self.sock = self.tls.wrap_socket(sock, server_hostname=self.host)


class Reply:
    def __init__(self, status, body):
        self.status = status
        self.body = body


class Server:
    """Sends requests the way an AnyConnect client does and keeps the
    cookies the server sets, as a client must to continue a login."""

    def __init__(self, address, port, vhost, output, log):
        self.conn = _VhostConnection(address, port, vhost)
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

    def post(self, body, path="/"):
        headers = {
            "User-Agent": "AnyConnect Darwin_i386 " + CLIENT_VERSION,
            "X-Transcend-Version": "1",
            "X-Aggregate-Auth": "1",
        }
        if self.cookies:
            headers["Cookie"] = "; ".join(
                "%s=%s" % c for c in self.cookies.items())
        self.trace(">", "POST %s" % path, body)
        self.conn.request("POST", path, body.encode(), headers)
        resp = self.conn.getresponse()
        reply = Reply(resp.status, resp.read().decode(errors="replace"))
        set_cookies = resp.msg.get_all("Set-Cookie") or []
        self.trace("<", "HTTP %d %s" % (resp.status, resp.reason),
              "".join("Set-Cookie: %s\n" % c for c in set_cookies)
              + reply.body)
        for cookie in set_cookies:
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


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

COMMANDS = {}


def arg(*flags, **options):
    return flags, options


def command(name, *arguments):
    """Registers a command; each argument is an arg(...) passed on to
    argparse. The function's docstring is the command's help."""
    def register(func):
        COMMANDS[name] = (func, arguments)
        return func
    return register


@command("groups",
         arg("--group", help="group to propose, as a client does with the "
             "group it used last"))
def cmd_groups(server, args):
    """Print the groups the login form offers, in the order offered, as
    'value<TAB>label' lines."""
    reply = server.post(init_request(group=args.group))
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


@command("login",
         arg("--group", help="group to propose, sent as given even if the "
             "form does not offer it"),
         arg("--user", required=True),
         arg("--password", required=True))
def cmd_login(server, args):
    """Log in with a username and password; succeed if the server issues
    a session cookie, refuse if it rejects the login."""
    reply = server.post(init_request(group=args.group))
    if reply.status != 200 or not asks_for_password(reply.body):
        raise ProtocolError("expected the login form, got HTTP %d"
                            % reply.status)
    reply = server.post(auth_reply(args.user, args.password, args.group))
    if reply.status == 401:
        server.report("login rejected")
        return REFUSED
    if reply.status == 200 and "webvpn" in server.cookies:
        server.report("session cookie issued")
        return OK
    raise ProtocolError("expected a session cookie or a rejection, got "
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
        sub = commands.add_parser(name, help=func.__doc__.split("\n")[0],
                                  description=func.__doc__)
        for flags, options in arguments:
            sub.add_argument(*flags, **options)
        sub.set_defaults(func=func)
    args = parser.parse_args()

    server = Server(args.address, args.port, args.host or args.address,
                    args.output, args.log)
    try:
        return args.func(server, args)
    except (ProtocolError, OSError, http.client.HTTPException) as e:
        print("ERROR: %s" % e, file=sys.stderr)
        if args.log is not sys.stderr:
            print("ERROR: %s" % e, file=args.log)
        return ERROR


if __name__ == "__main__":
    sys.exit(main())
