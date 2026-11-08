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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""Stand-in for main's occtl control socket, so that occtl's client-side
behavior can be tested without root and without a running server.

Usage: occtl-fake-server.py SOCKET SCENARIO LOGFILE

Every request received is appended to LOGFILE as "<command code>".
The SCENARIO selects how the server answers (see SCENARIOS below).
"""

import os
import socket
import struct
import sys

# src/occtl/ctl.h
CTL_CMD_STATUS = 1
CTL_CMD_LIST = 4
CTL_CMD_TOP = 11
CTL_CMD_LIST_COOKIES = 12

CTL_CMD_STATUS_REP = 101
CTL_CMD_LIST_REP = 104
CTL_CMD_TOP_UPDATE_REP = 109
CTL_CMD_LIST_COOKIES_REP = 110


def frame(cmd, payload=b""):
    """The framing of send_msg(): command byte, host-order length, body."""
    return struct.pack("=BI", cmd, len(payload)) + payload


def read_request(conn):
    """Reads one request; returns its command code or None on EOF."""
    hdr = b""
    while len(hdr) < 5:
        chunk = conn.recv(5 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    cmd, length = struct.unpack("=BI", hdr)
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            return None
        body += chunk
    return cmd


def silent(conn, cmd):
    """Reads the request and never answers."""
    while conn.recv(4096):
        pass


SCENARIOS = {
    "silent": silent,
}


def main():
    path, scenario, logfile = sys.argv[1:4]
    handler = SCENARIOS[scenario]

    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(8)

    while True:
        conn, _ = srv.accept()
        with conn:
            cmd = read_request(conn)
            if cmd is None:
                continue
            with open(logfile, "a") as f:
                f.write("%d\n" % cmd)
            handler(conn, cmd)


if __name__ == "__main__":
    main()
