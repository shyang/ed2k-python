#! /usr/bin/env python3

import hashlib
import io
import os
import sys

CHUNK_SIZE = 9728000

class Ed2k:
    def __init__(self, buf=b''):
        # keep pos always pointing to the end of stream
        self.hashset = io.BytesIO()
        self.buf = io.BytesIO(buf)
        if self.buf.seek(0, 2) > CHUNK_SIZE:
            self._hash()

    def update(self, buf):
        self.buf.write(buf)
        if self.buf.tell() > CHUNK_SIZE:
            self._hash()

    def _hash(self):
        self.buf.seek(0)
        buf = self.buf.read(CHUNK_SIZE)
        while len(buf) == CHUNK_SIZE:
            self.hashset.write(hashlib.new('md4', buf).digest())
            buf = self.buf.read(CHUNK_SIZE)
        else:
            self.buf = io.BytesIO(buf)
            self.buf.seek(0, 2)

    def hexdigest(self):
        self.buf.seek(0)
        if self.hashset.tell() > 0:
            self.hashset.write(hashlib.new('md4', self.buf.read()).digest())
            self.hashset.seek(0)
            buf = self.hashset.read()
            self.hashset.seek(-16, 2) # rollback last non-full chunk
            return hashlib.new('md4', buf).hexdigest()
        else:
            return hashlib.new('md4', self.buf.read()).hexdigest()

    @staticmethod
    def test():
        f = io.BytesIO(); f.seek(CHUNK_SIZE - 1); f.write(b'\x00'); f.seek(0);
        assert Ed2k(f.read()).hexdigest() == 'd7def262a127cd79096a108e7a9fc138'
        f = io.BytesIO(); f.seek(CHUNK_SIZE - 1); f.write(b'\x01'); f.seek(0);
        assert Ed2k(f.read()).hexdigest() == '68a002d06135444b4ea30e11f4324ee9'
        f = io.BytesIO(b'123456789')
        assert Ed2k(f.read()).hexdigest() == '2ae523785d0caf4d2fb557c12016185c'
        f = io.BytesIO(); f.seek(10000000 - 1); f.write(b'\x01'); f.seek(0);
        assert Ed2k(f.read()).hexdigest() == '7ab53cd47867f5fe5b031ddec3bc470e'

if __name__ == '__main__':
    Ed2k.test()
    block_size = 2 ** 18
    for f in sys.argv[1:]:
        if not os.path.isfile(f):
            continue
        hash = Ed2k()
        with open(f, 'rb') as srcfile:
            buf = srcfile.read(block_size)
            while buf:
                hash.update(buf)
                buf = srcfile.read(block_size)
            print(hash.hexdigest(), os.path.basename(f))

