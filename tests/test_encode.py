import unittest
from editrest.main import parse, encode


class TestEncodeDecode(unittest.TestCase):
    dictdata = {
        "key": "value"
    }
    arraydata = [{"key": "value"}, {"key2": "value2"}]

    def test_dict(self):
        for format in ["json", "pprint", "yaml", "toml"]:
            with self.subTest(format=format):
                data = encode(self.dictdata, format=format)
                newdata = parse(data, format=format)
                self.assertEqual(newdata, self.dictdata)

    def test_array(self):
        for format in ["json", "pprint", "yaml"]:  # toml does not support array?
            with self.subTest(format=format):
                data = encode(self.arraydata, format=format)
                newdata = parse(data, format=format)
                self.assertEqual(newdata, self.arraydata)

    def test_invalid(self):
        with self.assertRaises(NotImplementedError):
            encode(self.dictdata, format="unknown")
        with self.assertRaises(NotImplementedError):
            parse("hello world", format="unknown")
