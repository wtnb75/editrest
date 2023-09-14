import unittest
from unittest.mock import patch
from click.testing import CliRunner
from editrest.main import cli, NotChanged
import json
from logging import getLogger

_log = getLogger(__name__)


class TestCLI(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_version(self):
        res = CliRunner().invoke(cli, ["--version"])
        self.assertEqual(0, res.exit_code)
        self.assertIn("editrest", res.output)
        self.assertIn("version", res.output)

    def test_help(self):
        res = CliRunner().invoke(cli, ["--help"])
        self.assertEqual(0, res.exit_code)
        self.assertIn("--help", res.output)
        self.assertIn("--version", res.output)
        self.assertIn("get-put", res.output)
        self.assertIn("get-delete", res.output)
        self.assertIn("run", res.output)

    oldjson = {
        "key": "value",
    }
    oldtext = json.dumps(oldjson, ensure_ascii=False,
                         sort_keys=True, indent=2)
    newjson = {
        "key": "value123",
    }
    newtext = json.dumps(newjson)

    def test_get_put(self):
        with patch("requests.Session") as sess, \
                patch("editor.edit") as edit:
            edit.return_value = self.newtext
            sess.return_value.request.return_value.json.return_value = self.oldjson
            sess.return_value.request.return_value.status_code = 200
            res = CliRunner().invoke(cli, ["get-put", "url"], input="y\n")
            self.assertEqual(0, res.exit_code)
            edit.assert_called_once_with(contents=self.oldtext, suffix='.json')
            sess.return_value.request.assert_any_call('GET', 'url')
            sess.return_value.request.assert_any_call(
                'PUT', 'url', json=self.newjson)

    def test_get_post_unchannged(self):
        with patch("requests.Session") as sess, \
                patch("editor.edit") as edit:
            edit.return_value = json.dumps(self.oldjson)
            sess.return_value.request.return_value.json.return_value = self.oldjson
            sess.return_value.request.return_value.status_code = 200
            res = CliRunner().invoke(cli, ["get-put", "url"], input="y\n")
            self.assertEqual(1, res.exit_code)
            self.assertIsNotNone(res.exception)
            self.assertEqual(NotChanged, type(res.exception))
            edit.assert_called_once_with(contents=self.oldtext, suffix='.json')
            sess.return_value.request.assert_called_once_with('GET', 'url')

    def test_get_delete_no(self):
        with patch("requests.Session") as sess, \
                patch("editor.edit") as edit:
            edit.return_value = self.newtext
            sess.return_value.request.return_value.json.return_value = self.oldjson
            sess.return_value.request.return_value.status_code = 200
            res = CliRunner().invoke(cli, ["get-delete", "url"], input="n\n")
            self.assertEqual(1, res.exit_code)
            edit.assert_called_once_with(contents=self.oldtext, suffix='.json')
            sess.return_value.request.assert_called_once_with('GET', 'url')
            self.assertIsNotNone(res.exception)

    def test_get_put_dry(self):
        with patch("requests.Session") as sess, \
                patch("editor.edit") as edit:
            edit.return_value = json.dumps(self.newjson)
            sess.return_value.request.return_value.json.return_value = self.oldjson
            sess.return_value.request.return_value.status_code = 200
            res = CliRunner().invoke(cli, ["get-put", "url", "--dry"])
            self.assertEqual(0, res.exit_code)
            self.assertIn("(dry)", res.output)
