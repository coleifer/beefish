import getpass
import optparse
import os
import sys
import unittest
from random import randrange

from Crypto.Cipher import Blowfish
from Crypto import Random


def _gen_padding(fh):
    buflen = os.fstat(fh.fileno()).st_size
    pad_bytes = 8 - (buflen % 8)
    padding = Random.get_random_bytes(pad_bytes - 1)
    bflag = randrange(6, 248)
    bflag -= bflag % 8 - pad_bytes
    return padding + chr(bflag)

def _read_padding(buffer):
    return (ord(buffer[-1]) % 8) or 8

def encrypt(in_file, out_file, key, chunk_size=4096):
    in_fh = open(in_file, 'rb')
    out_fh = open(out_file, 'wb')

    padding = _gen_padding(in_fh)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    wrote_padding = False

    while 1:
        buffer = in_fh.read(chunk_size)
        if buffer:
            if len(buffer) < chunk_size:
                buffer += padding
                wrote_padding = True
            out_fh.write(cipher.encrypt(buffer))
        else:
            if not wrote_padding:
                out_fh.write(cipher.encrypt(padding))
            break

    in_fh.close()
    out_fh.close()

def decrypt(in_file, out_file, key, chunk_size=4096):
    in_fh = open(in_file, 'rb')
    out_fh = open(out_file, 'wb')
    
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted = ''
    
    while 1:
        buffer = in_fh.read(chunk_size)
        if buffer:
            decrypted = cipher.decrypt(buffer)
            out_fh.write(decrypted)
        else:
            break

    if decrypted:
        padding = _read_padding(decrypted)
        out_fh.seek(-padding, 2)
        out_fh.truncate()

    out_fh.close()
    in_fh.close()

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

    def write_bytes(self, num, ch='a'):
        buf = ch * num
        with open(self.in_filename, 'wb') as fh:
            fh.write(buf)
        return buf

    def crypt_data(self, num_bytes, ch, in_key=None, out_key=None, chunk_size=4096):
        in_key = in_key or self.key
        out_key = out_key or self.key

        buf = self.write_bytes(num_bytes, ch)
        encrypt(self.in_filename, self.out_filename, in_key, chunk_size)
        decrypt(self.out_filename, self.dec_filename, out_key, chunk_size)

        with open(self.dec_filename, 'rb') as fh:
            decrypted = fh.read()

        return buf, decrypted

    def test_encrypt_decrypt(self):
        def encrypt_flow(ch):
            for i in range(17):
                buf, decrypted = self.crypt_data(i, ch)
                self.assertEqual(buf, decrypted)

        encrypt_flow('a')
        encrypt_flow('\x00')
        encrypt_flow('\x01')
        encrypt_flow('\xff')

    def test_key(self):
        buf, decrypted = self.crypt_data(128, 'a', self.key, self.key+'x')
        self.assertNotEqual(buf, decrypted)

    def test_chunk_sizes(self):
        for i in [128, 1024, 2048, 4096]:
            nb = [i - 1, i, i + 1, i * 2, i * 2 + 1]
            for num_bytes in nb:
                buf, decrypted = self.crypt_data(num_bytes, 'a', chunk_size=i)
                self.assertEqual(buf, decrypted)


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
                print 'Keys did not match'
    else:
        key = options.key

    infile, outfile = args[0], args[1]
    if os.path.exists(outfile):
        print '%s will be overwritten' % outfile
        if raw_input('Continue? yN ') != 'y':
            sys.exit(2)

    if options.encrypt:
        encrypt(infile, outfile, key)
    else:
        decrypt(infile, outfile, key)
