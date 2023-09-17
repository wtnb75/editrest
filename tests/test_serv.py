import unittest
from unittest.mock import patch
import os
import threading
import json
import tempfile
import requests
import ssl
from contextlib import contextmanager
from OpenSSL import crypto
from logging import getLogger
from http.server import BaseHTTPRequestHandler, HTTPServer
from editrest.main import cli
from click.testing import CliRunner

_log = getLogger(__name__)


class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        respdata = {"hello": "world"}
        _log.info("client: %s %s", self.address_string(), self.requestline)
        _log.info("request: method=%s, path=%s, version=%s, hdr=%s",
                  self.command, self.path, self.version_string(), self.headers)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(respdata).encode('utf-8'))

    def do_POST(self):
        respdata = {"result": "ok"}
        clen = int(self.headers.get('content-length'))
        json.loads(self.rfile.read(clen).decode('utf-8'))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_headers()
        self.wfile.write(json.dumps(respdata).encode("utf-8"))


class TestHTTPS(unittest.TestCase):
    def _mkcert(self, cname: str) -> tuple[crypto.PKey, crypto.X509]:
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        c = crypto.X509()
        c.get_subject().countryName = 'XX'  # country code
        c.get_subject().stateOrProvinceName = 'dummy state'
        c.get_subject().localityName = 'dummy region'
        c.get_subject().organizationName = 'dummy org'
        c.get_subject().organizationalUnitName = 'dummy org unit'
        c.get_subject().commonName = cname
        c.set_serial_number(1)
        c.gmtime_adj_notBefore(0)
        c.gmtime_adj_notAfter(60*60*24*365*10)
        c.set_pubkey(k)
        return k, c

    def _sign_cert(self, target: crypto.X509, key: crypto.PKey, cert: crypto.X509):
        target.set_issuer(cert.get_subject())
        target.sign(key, 'sha256')

    def _make_ca(self, td: str, cname: str):
        self.cakey, self.cacert = self._mkcert(cname)
        self._sign_cert(self.cacert, self.cakey, self.cacert)
        self.cakey_b = crypto.dump_privatekey(crypto.FILETYPE_PEM, self.cakey)
        self.cacert_b = crypto.dump_certificate(
            crypto.FILETYPE_PEM, self.cacert)
        with open(os.path.join(td, "ca.crt"), "wb") as cacrt:
            cacrt.write(self.cacert_b)

    @contextmanager
    def _boot_server0(self):
        srv = HTTPServer(('127.0.0.1', 0), MyHandler)
        try:
            th = threading.Thread(target=srv.serve_forever)
            th.start()
            yield srv
        finally:
            srv.shutdown()
            th.join()

    @contextmanager
    def _boot_server1(self, key: crypto.PKey, cert: crypto.X509):
        srv = HTTPServer(('127.0.0.1', 0), MyHandler)
        ctxt = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH, cafile=os.path.join(self.td.name, "ca.crt"))
        with open(os.path.join(self.td.name, "srv.crt"), "wb") as srvcrt:
            srvcrt.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            srvcrt.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        ctxt.load_cert_chain(os.path.join(self.td.name, "srv.crt"))
        ctxt.check_hostname = False
        srv.socket = ctxt.wrap_socket(srv.socket, server_side=True)
        try:
            th = threading.Thread(target=srv.serve_forever)
            th.start()
            yield srv
        finally:
            srv.shutdown()
            th.join()

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self._make_ca(self.td.name, "ca.local")

    def tearDown(self):
        del self.td

    def test_nossl(self):
        srvhost = "server.local"
        with self._boot_server0() as srv, \
                patch("editor.edit") as edit:
            edit.return_value = b'{"hello": true}'
            host = srvhost
            port = srv.server_address[1]
            res = CliRunner().invoke(
                cli, ["get-post", "--dry", f"http://{host}:{port}/example",
                      "--resolve", f"{host}:127.0.0.1", "--quiet"])
            _log.debug("res %s output=%s", res.exit_code,
                       res.output, exc_info=res.exc_info)
            self.assertEqual(0, res.exit_code)

    def test_ssl1(self):
        srvhost = "server.local"
        srvkey, srvcert = self._mkcert(srvhost)
        self._sign_cert(srvcert, self.cakey, self.cacert)
        with self._boot_server1(srvkey, srvcert) as srv, \
                patch("editor.edit") as edit:
            edit.return_value = b'{"hello": true}'
            host = srvhost
            port = srv.server_address[1]
            res = CliRunner().invoke(
                cli, ["get-post", "--dry", f"https://{host}:{port}/example",
                      "--resolve", f"{host}:{port}:127.0.0.1",
                      "--cacert", os.path.join(self.td.name, "ca.crt")])
            _log.debug("res %s output=%s", res.exit_code,
                       res.output, exc_info=res.exc_info)
            self.assertEqual(0, res.exit_code)

    def test_ssl2(self):
        srvhost = "server.local"
        srvkey, srvcert = self._mkcert(srvhost)
        self._sign_cert(srvcert, self.cakey, self.cacert)
        with self._boot_server1(srvkey, srvcert) as srv, \
                patch("editor.edit") as edit:
            edit.return_value = b'{"hello": true}'
            host = srvhost
            port = srv.server_address[1]
            res = CliRunner().invoke(
                cli, ["get-post", "--dry", f"https://{host}.invalid:{port}/example",
                      "--resolve", f"{host}.invalid:{port}:127.0.0.1", "--verbose",
                      "--cacert", os.path.join(self.td.name, "ca.crt")])
            _log.debug("res %s output=%s", res.exit_code,
                       res.output, exc_info=res.exc_info)
            self.assertEqual(1, res.exit_code)
            self.assertIsInstance(res.exception, requests.exceptions.SSLError)
