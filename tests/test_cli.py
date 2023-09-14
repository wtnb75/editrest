import unittest
from click.testing import CliRunner
from editrest.main import cli


class TestCLI(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_help(self):
        res = CliRunner().invoke(cli, ["--version"])
        self.assertEqual(0, res.exit_code)
        self.assertIn("editrest", res.output)
        self.assertIn("version", res.output)
