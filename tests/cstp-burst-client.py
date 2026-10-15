#!/usr/bin/env python3
#
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""A raw CSTP client for test-cstp-burst.

It opens the tunnel with a CONNECT request that carries a session cookie,
then sends CSTP packets back to back, each in its own TLS record, so that
the worker finds several records ready at once:

  echo  one ICMP echo request to the target, then a burst of them; every
        reply must arrive while the client sends nothing more.
  bad   a few echo requests, then a record whose CSTP header is not
        valid; the server must close the connection.
"""

import argparse
import ipaddress
import os
import socket
import ssl
import struct
import sys
import time

AC_PKT_DATA = 0
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


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
    def __init__(self, host, port, cookie):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            sock = socket.create_connection((host, port), timeout=10)
            self.tls = ctx.wrap_socket(sock, server_hostname=host)
        except OSError as e:
            fail("cannot connect to %s:%d: %s" % (host, port, e))
        self.tls.sendall(("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "User-Agent: Open AnyConnect VPN Agent v9.12\r\n"
                          "Cookie: webvpn=%s\r\n"
                          "X-CSTP-Version: 1\r\n"
                          "X-CSTP-Hostname: cstp-burst\r\n"
                          "X-CSTP-Address-Type: IPv4\r\n"
                          "\r\n" % (host, cookie)).encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            data = self.tls.recv(4096)
            if not data:
                fail("connection closed before the end of the CONNECT "
                     "reply: %r" % self.buf)
            self.buf += data
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if not lines[0].startswith("HTTP/1.1 200"):
            fail("CONNECT refused: %s" % lines[0])
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
            fail("no IPv4 X-CSTP-Address in the CONNECT reply")

    def send(self, records):
        # one sendall() per record: each goes out in its own TLS record
        for record in records:
            self.tls.sendall(record)

    def receive(self, timeout, handle):
        """Call handle(type, payload) for each CSTP packet received, until
        it returns True ("done"), the server closes the connection
        ("closed") or timeout seconds pass ("timeout")."""
        deadline = time.monotonic() + timeout
        while True:
            while len(self.buf) >= 8:
                if self.buf[:4] != b"STF\x01":
                    fail("unexpected data from the server: %r" %
                         self.buf[:16])
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("mode", choices=["echo", "bad"])
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cookie", required=True)
    parser.add_argument("--target", type=ipaddress.IPv4Address,
                        required=True,
                        help="the server's address in the tunnel")
    parser.add_argument("--count", type=int, default=20,
                        help="echo requests sent back to back")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()

    tun = Tunnel(args.host, args.port, args.cookie)
    ident = os.getpid() & 0xFFFF
    replies = set()

    def requests(seqs):
        return [cstp_record(echo_request(tun.address, args.target, ident, s))
                for s in seqs]

    def await_replies(seqs, what):
        def handle(packet_type, payload):
            if packet_type == AC_PKT_DATA:
                seq = echo_reply_seq(payload, args.target, tun.address, ident)
                if seq is not None:
                    replies.add(seq)
            return replies.issuperset(seqs)

        result = tun.receive(args.timeout, handle)
        if result != "done":
            missing = sorted(set(seqs) - replies)
            fail("%s: no reply to echo request(s) %s (connection %s)" %
                 (what, missing, result))
        print("ok: %s answered" % what)

    if args.mode == "echo":
        # The worker reads the one record there is, and must then go
        # back to its event loop to forward the reply from the TUN device.
        tun.send(requests([0]))
        await_replies([0], "a single echo request")
        burst = range(1, args.count + 1)
        tun.send(requests(burst))
        await_replies(burst, "%d echo requests sent back to back" % args.count)
    else:
        bad_header = b"XTF\x01" + struct.pack("!HBB", 0, AC_PKT_DATA, 0)
        tun.send(requests(range(3)) + [bad_header])
        result = tun.receive(args.timeout, lambda packet_type, payload: False)
        if result != "closed":
            fail("the connection was still open %g s after a record with a "
                 "malformed CSTP header" % args.timeout)
        print("ok: the server closed the connection after a malformed record")


if __name__ == "__main__":
    main()
