from unittest import TestCase

from cipher21.bytes_utils import unhexlify


class UnhexlifyTest(TestCase):

    def test_positive_cases(self):
        self.assertEqual(bytearray(), unhexlify(b''))
        self.assertEqual(bytearray(), unhexlify(b' '))
        self.assertEqual(bytearray(), unhexlify(b'\r\n'))
        self.assertEqual(bytearray((0x00,)), unhexlify(b'00'))
        self.assertEqual(bytearray((0xA5,)), unhexlify(b'a:5'))
        self.assertEqual(bytearray((0xC8, 0xDF, 0x40, 0xe8, 0xB6, 0xE1, 0x1B)),
                         unhexlify(b'c8:dF:40:e8:B6:e1:1b'))
        self.assertEqual(bytearray((0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF)),
                         unhexlify(b'0123456789ABCDEF'))
        self.assertEqual(bytearray((0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF)),
                         unhexlify(b'0123456789abcdef'))
        self.assertEqual(bytearray((0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10)),
                         unhexlify(b'Fe.Dc:Ba 98\t76\n54\r\n3210'))

    def test_negative_cases(self):
        with self.assertRaises(ValueError):
            unhexlify(b'x')
        with self.assertRaises(ValueError):
            unhexlify(b' A\n')
        with self.assertRaises(ValueError):
            unhexlify(b'764d52a83a657')
        with self.assertRaises(ValueError):
            unhexlify(b'0x764d52a83a657A')
