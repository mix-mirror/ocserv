#!/usr/bin/env python3
#
# Copyright (C) 2026 Konstantin Satvaldyev
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
"""A minimal OpenID Connect provider, enough to drive the authorization
code flow in the test suite.

It answers the three requests ocserv makes of a provider: the metadata
document, the JWKS, and the token endpoint. The authorization endpoint is
answered as well, so that a script standing in for the browser can follow
it. Tokens are signed by gen_oidc_test_data, which owns the key.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import urllib.parse
import uuid


class Provider(http.server.BaseHTTPRequestHandler):
    # code -> the nonce and the PKCE challenge of the request it belongs to
    pending = {}
    # exchanges refused because the verifier did not match the challenge,
    # so that a test can tell PKCE is what refused them
    pkce_failures = 0
    # code -> how many times it was presented at the token endpoint, so
    # that a test can tell whether a replay reached the provider
    exchanges = {}
    # claims to put in the next token instead of the defaults, set
    # through /next-token
    next_claims = {}

    def log_message(self, fmt, *args):
        sys.stderr.write("mock-provider: " + (fmt % args) + "\n")

    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def metadata(self):
        base = self.server.base_url
        self.send_json({
            "issuer": self.server.issuer,
            "jwks_uri": base + "/jwks",
            "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token",
        })

    def jwks(self):
        with open(os.path.join(self.server.datadir, "keys.json")) as f:
            self.send_json(json.load(f))

    def authorize(self, query):
        args = urllib.parse.parse_qs(query)

        redirect_uri = args.get("redirect_uri", [None])[0]
        state = args.get("state", [None])[0]
        nonce = args.get("nonce", [""])[0]
        challenge = args.get("code_challenge", [None])[0]
        method = args.get("code_challenge_method", [None])[0]

        if redirect_uri is None or state is None:
            self.send_error(400, "missing redirect_uri or state")
            return

        # ocserv always uses PKCE, with the S256 method (RFC 7636)
        if challenge is None or method != "S256":
            self.send_error(400, "missing or plain PKCE challenge")
            return

        code = uuid.uuid4().hex
        Provider.pending[code] = (nonce, challenge)

        sep = "&" if "?" in redirect_uri else "?"
        target = "%s%scode=%s&state=%s" % (
            redirect_uri, sep, urllib.parse.quote(code),
            urllib.parse.quote(state))

        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def token(self):
        length = int(self.headers.get("Content-Length", 0))
        args = urllib.parse.parse_qs(self.rfile.read(length).decode())

        code = args.get("code", [None])[0]
        Provider.exchanges[code] = Provider.exchanges.get(code, 0) + 1

        # a code is good for one exchange only
        request = Provider.pending.pop(code, None)
        if request is None:
            self.send_json({"error": "invalid_grant"}, status=400)
            return
        nonce, challenge = request

        # the verifier must hash to the challenge of the request the code
        # was issued for (RFC 7636 section 4.6)
        verifier = args.get("code_verifier", [""])[0]
        digest = hashlib.sha256(verifier.encode()).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != challenge:
            Provider.pkce_failures += 1
            self.send_json({"error": "invalid_grant"}, status=400)
            return

        # a test may ask for a nonce other than the one of the request,
        # to see that ocserv checks it
        nonce = Provider.next_claims.pop("nonce", nonce)

        argv = [self.server.minter, "--mint", self.server.user, nonce]
        argv += self.server.groups

        env = dict(os.environ)
        env["OIDC_MINT_AUD"] = self.server.audience
        env.update(Provider.next_claims)
        Provider.next_claims = {}

        proc = subprocess.run(argv, capture_output=True, env=env,
                              cwd=os.path.dirname(self.server.datadir))
        if proc.returncode != 0:
            self.log_message("minting failed: %s", proc.stderr.decode())
            self.send_json({"error": "server_error"}, status=500)
            return

        self.send_json({
            "access_token": "unused",
            "token_type": "Bearer",
            "id_token": proc.stdout.decode().strip(),
        })

    def set_next_token(self, query):
        args = urllib.parse.parse_qs(query)
        Provider.next_claims = {}
        if "aud" in args:
            Provider.next_claims["OIDC_MINT_AUD"] = args["aud"][0]
        if "azp" in args:
            Provider.next_claims["OIDC_MINT_AZP"] = args["azp"][0]
        if "iss" in args:
            Provider.next_claims["OIDC_MINT_ISS"] = args["iss"][0]
        if "nonce" in args:
            Provider.next_claims["nonce"] = args["nonce"][0]
        self.send_response(204)
        self.end_headers()

    def count_pkce_failures(self):
        body = str(Provider.pkce_failures).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def count_exchanges(self, query):
        code = urllib.parse.parse_qs(query).get("code", [None])[0]
        body = str(Provider.exchanges.get(code, 0)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")

        if path == "/.well-known/openid-configuration":
            self.metadata()
        elif path == "/jwks":
            self.jwks()
        elif path == "/authorize":
            self.authorize(query)
        elif path == "/exchanges":
            self.count_exchanges(query)
        elif path == "/next-token":
            self.set_next_token(query)
        elif path == "/pkce-failures":
            self.count_pkce_failures()
        else:
            self.send_error(404)

    def do_POST(self):
        path, _, _ = self.path.partition("?")

        if path == "/token":
            self.token()
        else:
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.3")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--datadir", required=True,
                        help="where keys.json and oidc-key.json live")
    parser.add_argument("--minter", required=True,
                        help="path to gen_oidc_test_data")
    parser.add_argument("--user", default="SomeUser")
    parser.add_argument("--issuer", default="SomeIssuer")
    parser.add_argument("--audience", default="SomeAudience",
                        help="the audience of the tokens issued; several "
                        "separated by commas")
    parser.add_argument("--group", action="append", default=[])
    args = parser.parse_args()

    server = http.server.HTTPServer((args.address, args.port), Provider)
    server.base_url = "http://%s:%d" % (args.address, args.port)
    server.datadir = args.datadir
    server.minter = args.minter
    server.user = args.user
    server.issuer = args.issuer
    server.audience = args.audience
    server.groups = args.group

    server.serve_forever()


if __name__ == "__main__":
    main()
