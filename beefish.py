#!/usr/bin/env python
import getpass
import optparse
import os
import struct
import sys
import unittest
from random import randrange

PY3 = sys.version_info[0] == 3
if PY3:
    import builtins
    print_ = getattr(builtins, 'print')
    raw_input = getattr(builtins, 'input')
else:
    def print_(s):
        sys.stdout.write(s)
        sys.stdout.write('\n')

from io import BytesIO

from Crypto.Cipher import Blowfish
from Crypto import Random


def _gen_padding(file_size, block_size):
    pad_bytes = block_size - (file_size % block_size)
    padding = Random.get_random_bytes(pad_bytes - 1)
    bflag = randrange(block_size - 2, 256 - block_size)
    bflag -= bflag % block_size - pad_bytes
    return padding + chr(bflag).encode('raw_unicode_escape')

def _read_padding(buffer, block_size):
    return (buffer[-1] % block_size) or block_size

def generate_iv(block_size):
    return Random.get_random_bytes(block_size)

def get_cipher(key, iv):
    return Blowfish.new(key, Blowfish.MODE_CBC, iv)

def encrypt(in_buf, out_buf, key, chunk_size=4096):
    iv = generate_iv(Blowfish.block_size)
    cipher = get_cipher(key, iv)
    bytes_read = 0
    wrote_padding = False

    out_buf.write(iv)

    while 1:
        buffer = in_buf.read(chunk_size)
        buffer_len = len(buffer)
        bytes_read += buffer_len
        if buffer:
            if buffer_len < chunk_size:
                buffer += _gen_padding(bytes_read, cipher.block_size)
                wrote_padding = True
            out_buf.write(cipher.encrypt(buffer))
        else:
            if not wrote_padding:
                out_buf.write(cipher.encrypt(_gen_padding(bytes_read, cipher.block_size)))
            break

def decrypt(in_buf, out_buf, key, chunk_size=4096):
    iv = in_buf.read(Blowfish.block_size)

    cipher = get_cipher(key, iv)
    decrypted = ''

    while 1:
        buffer = in_buf.read(chunk_size)
        if buffer:
            decrypted = cipher.decrypt(buffer)
            out_buf.write(decrypted)
        else:
            break

    if decrypted:
        padding = _read_padding(decrypted, cipher.block_size)
        out_buf.seek(-padding, 2)
        out_buf.truncate()

def encrypt_file(in_file, out_file, key, chunk_size=4096):
    with open(in_file, 'rb') as in_fh:
        with open(out_file, 'wb') as out_fh:
            encrypt(in_fh, out_fh, key, chunk_size)

def decrypt_file(in_file, out_file, key, chunk_size=4096):
    with open(in_file, 'rb') as in_fh:
        with open(out_file, 'wb') as out_fh:
            decrypt(in_fh, out_fh, key, chunk_size)

class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.in_filename = '/tmp/crypt.tmp.in'
        self.out_filename = '/tmp/crypt.tmp.out'
        self.dec_filename = '/tmp/crypt.tmp.dec'
        self.key = 'testkey'

    def tearDown(self):
        self.remove_files(
            self.in_filename,
            self.out_filename,
            self.dec_filename,
        )

    def remove_files(self, *filenames):
        for fn in filenames:
            if os.path.exists(fn):
                os.unlink(fn)

    def write_bytes(self, num, ch=b'a'):
        buf = ch * num
        with open(self.in_filename, 'wb') as fh:
            fh.write(buf)
        return buf

    def crypt_data(self, num_bytes, ch, in_key=None, out_key=None, chunk_size=4096):
        in_key = in_key or self.key
        out_key = out_key or self.key

        buf = self.write_bytes(num_bytes, ch)
        encrypt_file(self.in_filename, self.out_filename, in_key, chunk_size)
        decrypt_file(self.out_filename, self.dec_filename, out_key, chunk_size)

        with open(self.dec_filename, 'rb') as fh:
            decrypted = fh.read()

        return buf, decrypted

    def test_encrypt_decrypt(self):
        def encrypt_flow(ch):
            for i in range(17):
                buf, decrypted = self.crypt_data(i, ch)
                self.assertEqual(buf, decrypted)

        encrypt_flow(b'a')
        encrypt_flow(b'\x00')
        encrypt_flow(b'\x01')
        encrypt_flow(b'\xff')

    def test_key(self):
        buf, decrypted = self.crypt_data(128, b'a', self.key, self.key+'x')
        self.assertNotEqual(buf, decrypted)

    def test_chunk_sizes(self):
        for i in [128, 1024, 2048, 4096]:
            nb = [i - 1, i, i + 1, i * 2, i * 2 + 1]
            for num_bytes in nb:
                buf, decrypted = self.crypt_data(num_bytes, b'a', chunk_size=i)
                self.assertEqual(buf, decrypted)

    def test_stringio(self):
        for i in [128, 1024, 2048, 4096]:
            nb = [i - 1, i, i + 1, i * 2, i * 2 + 1]
            for num_bytes in nb:
                in_buf = BytesIO()
                out_buf = BytesIO()
                dec_buf = BytesIO()
                in_buf.write(num_bytes * b'a')
                in_buf.seek(0)
                encrypt(in_buf, out_buf, self.key, i)
                out_buf.seek(0)
                decrypt(out_buf, dec_buf, self.key, i)
                self.assertEqual(in_buf.getvalue(), dec_buf.getvalue())


if __name__ == '__main__':
    parser = optparse.OptionParser(usage='%prog [-e|-d] INFILE OUTFILE')
    parser.add_option('-t', '--test', dest='run_tests', action='store_true')
    parser.add_option('-k', '--key', dest='key', action='store', type='str')
    parser.add_option('-e', '--encrypt', dest='encrypt', action='store_true')
    parser.add_option('-d', '--decrypt', dest='decrypt', action='store_true')
    parser.add_option('-q', '--quiet', dest='quiet', action='store_true')
    (options, args) = parser.parse_args()

    if options.run_tests:
        unittest.main(argv=sys.argv[:1], verbosity=not options.quiet and 2 or 0)

    if len(args) == 1:
        if options.encrypt:
            default = '%s.e' % args[0]
        else:
            default = args[0].rstrip('.e')
        args.append(raw_input('Destination? (%s) ' % default) or default)

    if len(args) < 2 or not (options.encrypt or options.decrypt):
        parser.print_help()
        sys.exit(1)

    if not options.key:
        while 1:
            key = getpass.getpass('Key: ')
            verify = getpass.getpass('Verify: ')
            if key == verify:
                break
            else:
                print_('Keys did not match')
    else:
        key = options.key

    infile, outfile = args[0], args[1]
    if os.path.exists(outfile):
        print_('%s will be overwritten' % outfile)
        if raw_input('Continue? yN ') != 'y':
            sys.exit(2)

    if options.encrypt:
        encrypt_file(infile, outfile, key)
    else:
        decrypt_file(infile, outfile, key)
