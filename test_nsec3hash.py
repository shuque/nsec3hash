#!/usr/bin/env python3

"""
Unit tests for nsec3hash()
"""

import unittest
from nsec3hash import nsec3hash


TEST_VECTORS = [
    [('9EBA4228', 1, 0, 'appforce.com.'), '8J1MO1GNFAB00QV63ROFSL7DBDQU0QN2'],
    [('', 1, 0, 'com.'), 'CK0POJMG874LJREF7EFN8430QVIT8BSM'],
    [('4C44934802D3', 1, 8, 'verisign.com.'), 'LVNT2DK6E38UB5HG27E7MCINT8M21C9P'],
    [('4AB238F7CD74D23D', 1, 50, 'toshiba.com.'), '7QN218CACBDEVNJIT57L56TRVR6RRHBP'],
]


class TestHashing(unittest.TestCase):

    """Test class for NSEC3 hashes"""

    def setUp(self):
        pass

    def test_all(self):
        """Run tests on all test vectors"""
        for vector in TEST_VECTORS:
            with self.subTest(vector=vector):
                data, hashvalue = vector
                salt, algnum, iterations, name = data
                self.assertEqual(nsec3hash(name, algnum, salt, iterations),
                                 hashvalue)


if __name__ == '__main__':
    unittest.main()
