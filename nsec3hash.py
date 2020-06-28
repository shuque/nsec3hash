#!/usr/bin/env python3

"""
nsec3 hash calculator

"""

import os
import sys
import hashlib
import base64
import dns.name

B32_TO_EXT_HEX = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                 b'0123456789ABCDEFGHIJKLMNOPQRSTUV')


def usage():
    """Print usage string and exit"""
    print("""\
Usage: {0} <salt> <algorithm> <iterations> <domain-name>

       salt:        salt in hexadecimal string form
       algorithm:   must be 1 (SHA1)
       iterations:  number of iterations of the hash function
       domain-name: the domain-name
""".format(PROGNAME))
    sys.exit(1)


def hashalg(algnum):
    """Return hash function corresponding to hash algorithm number"""
    if algnum == 1:
        return hashlib.sha1
    else:
        raise ValueError("unsupported NSEC3 hash algorithm {}".format(algnum))


def nsec3hash(name, algnum, salt, iterations, binary_out=False):

    """Compute NSEC3 hash for given domain name and parameters"""

    if iterations < 0:
        raise ValueError("iterations must be >= 0")
    wire_name = dns.name.from_text(name).canonicalize().to_wire()
    wire_salt = bytes.fromhex(salt)
    hashfunc = hashalg(algnum)
    digest = wire_name
    while iterations >= 0:
        digest = hashfunc(digest + wire_salt).digest()
        iterations -= 1
    if binary_out:
        return digest
    output = base64.b32encode(digest)
    output = output.translate(B32_TO_EXT_HEX).decode()
    return output


if __name__ == '__main__':

    PROGNAME = os.path.basename(sys.argv[0])
    if len(sys.argv) != 5:
        usage()

    SALT, ALGNUM, ITERATIONS, NAME = sys.argv[1:5]
    ALGNUM = int(ALGNUM)
    ITERATIONS = int(ITERATIONS)
    print(nsec3hash(NAME, ALGNUM, SALT, ITERATIONS))
