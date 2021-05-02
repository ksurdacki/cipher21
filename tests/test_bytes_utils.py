from unittest import TestCase

from cipher21.bytes_utils import *


class BytesUtilsTest(TestCase):

    def test_unhexlify(self):
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
                         unhexlify(b'Fe.Dc:Ba 98\t76\n54\r\n3,2;1-0'))
        with self.assertRaises(ValueError):
            unhexlify(b'x')
        with self.assertRaises(ValueError):
            unhexlify(b' A\n')
        with self.assertRaises(ValueError):
            unhexlify(b'764d52a83a657')
        with self.assertRaises(ValueError):
            unhexlify(b'??')
        with self.assertRaises(ValueError):
            unhexlify(b'0x764d52a83a657A')
        with self.assertRaises(TypeError):
            unhexlify(None)
        with self.assertRaises(TypeError):
            unhexlify('ab')
        with self.assertRaises(TypeError):
            unhexlify(0xab)

    def test_count_unique_bytes(self):
        self.assertEqual(0, count_unique_bytes(bytes()))
        self.assertEqual(1, count_unique_bytes(bytes((0,))))
        self.assertEqual(1, count_unique_bytes(bytes((0, 0))))
        self.assertEqual(2, count_unique_bytes(bytes((1, 0))))
        self.assertEqual(2, count_unique_bytes(bytes((0, 1, 0))))
        self.assertEqual(1, count_unique_bytes(bytes((33, 33, 33))))
        self.assertEqual(3, count_unique_bytes(bytes((123, 234, 0, 123))))
        self.assertEqual(100, count_unique_bytes(bytes(range(100))))
        self.assertEqual(256, count_unique_bytes(bytes(range(256))))
        self.assertEqual(256, count_unique_bytes(4*bytes(range(256))))
        self.assertEqual(128, count_unique_bytes(8*bytes(range(128))))
        self.assertEqual(100, count_unique_bytes(bytes(range(100, 200))))
        self.assertEqual(25, count_unique_bytes(5*bytes(range(100, 200, 4))))
        self.assertEqual(1, count_unique_bytes(1000*b'x'))

    def test_differentiate_bytes(self):
        self.assertEqual(b'', differentiate_bytes(b''))
        self.assertEqual(b'', differentiate_bytes(b'~'))
        self.assertEqual(b'\x01', differentiate_bytes(b'\x00\x01'))
        self.assertEqual(b'\x01', differentiate_bytes(b'xy'))
        self.assertEqual(b'\xFE', differentiate_bytes(b'ca'))
        self.assertEqual(b'\x00\x01\xFE\x03\xFC\x05\xFA\x07\xF8',
                         differentiate_bytes(b'\x80\x80\x81\x7F\x82\x7E\x83\x7D\x84\x7C'))

    def test_clear_secret(self):
        b = bytearray(2**12)
        clear_secret(b)
        self.assertEqual(256, count_unique_bytes(b))
