#!/usr/bin/env python
import getpass
import optparse
import os
import struct
import sys
import unittest
from hashlib import sha256
from random import randrange

PY3 = sys.version_info[0] == 3
if PY3:
    import builtins
    print_ = getattr(builtins, 'print')
    raw_input = getattr(builtins, 'input')
    unicode_type = str
    # PyCrypto uses time.clock internally, which was removed in 3.8. We'll just
    # patch it in for now.
    if sys.version_info >= (3, 8, 0):
        import time
        time.clock = time.process_time
else:
    unicode_type = unicode
    def print_(s):
        sys.stdout.write(s)
        sys.stdout.write('\n')

from io import BytesIO

from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto import Random


CIPHER_BLOWFISH = 1
CIPHER_AES = 2


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

def get_blowfish_cipher(key, iv):
    return Blowfish.new(key, Blowfish.MODE_CBC, iv)

def get_aes_cipher(key, iv):
    if isinstance(key, unicode_type):
        key = key.encode('utf-8')

    iv_length = AES.block_size  # 16.
    key_length = 32
    key_iv_length = iv_length + key_length
    d = d_i = b''
    while len(d) < key_iv_length:
        d_i = sha256(d_i + key).digest()
        d += d_i[:16]

    new_key = d[:key_length]
    new_iv = d[key_length:key_iv_length]
    return AES.new(new_key, AES.MODE_CBC, new_iv)

CIPHER_MAP = {
    CIPHER_BLOWFISH: (get_blowfish_cipher, Blowfish.block_size),
    CIPHER_AES: (get_aes_cipher, AES.block_size),
}

def encrypt(in_buf, out_buf, key, chunk_size=4096,
            cipher_type=CIPHER_BLOWFISH):
    get_cipher, block_size = CIPHER_MAP[cipher_type]

    iv = generate_iv(block_size)
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
                buffer += _gen_padding(bytes_read, block_size)
                wrote_padding = True
            out_buf.write(cipher.encrypt(buffer))
        else:
            if not wrote_padding:
                padding = _gen_padding(bytes_read, block_size)
                out_buf.write(cipher.encrypt(padding))
            break

def decrypt(in_buf, out_buf, key, chunk_size=4096,
            cipher_type=CIPHER_BLOWFISH):
    get_cipher, block_size = CIPHER_MAP[cipher_type]
    iv = in_buf.read(block_size)

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
        padding = _read_padding(decrypted, block_size)
        out_buf.seek(-padding, 2)
        out_buf.truncate()

def encrypt_file(in_file, out_file, key, chunk_size=4096,
                 cipher_type=CIPHER_BLOWFISH):
    with open(in_file, 'rb') as in_fh:
        with open(out_file, 'wb') as out_fh:
            encrypt(in_fh, out_fh, key, chunk_size, cipher_type)

def decrypt_file(in_file, out_file, key, chunk_size=4096,
                 cipher_type=CIPHER_BLOWFISH):
    with open(in_file, 'rb') as in_fh:
        with open(out_file, 'wb') as out_fh:
            decrypt(in_fh, out_fh, key, chunk_size, cipher_type)

class TestEncryptDecrypt(unittest.TestCase):
    cipher_type = CIPHER_BLOWFISH

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
        encrypt_file(self.in_filename, self.out_filename, in_key, chunk_size,
                     self.cipher_type)
        decrypt_file(self.out_filename, self.dec_filename, out_key, chunk_size,
                     self.cipher_type)

        with open(self.dec_filename, 'rb') as fh:
            decrypted = fh.read()

        return buf, decrypted

    def test_encrypt_decrypt(self):
        def encrypt_flow(ch):
            for i in range(33):
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
                encrypt(in_buf, out_buf, self.key, i, self.cipher_type)
                out_buf.seek(0)
                decrypt(out_buf, dec_buf, self.key, i, self.cipher_type)
                self.assertEqual(in_buf.getvalue(), dec_buf.getvalue())

    def test_cipher_stability(self):
        get_cipher, block_size = CIPHER_MAP[self.cipher_type]
        make_cipher = lambda: get_cipher(b'passphrase', b'\x00' * block_size)

        # Test that the same passphrase and IV yield same ciphertext.
        data = 'a' * block_size * 4
        crypt_data1 = make_cipher().encrypt(data)
        crypt_data2 = make_cipher().encrypt(data)
        self.assertEqual(crypt_data1, crypt_data2)


class TestEncryptDecryptAES(TestEncryptDecrypt):
    cipher_type = CIPHER_AES


if __name__ == '__main__':
    parser = optparse.OptionParser(usage='%prog [-e|-d] INFILE OUTFILE')
    parser.add_option('-e', '--encrypt', dest='encrypt', action='store_true')
    parser.add_option('-d', '--decrypt', dest='decrypt', action='store_true')
    parser.add_option('-k', '--key', dest='key', action='store', type='str')
    parser.add_option('-a', '--aes', dest='aes', action='store_true',
                      help='Use AES256 cipher (default is blowfish).')
    parser.add_option('-t', '--test', dest='run_tests', action='store_true')
    parser.add_option('-q', '--quiet', dest='quiet', action='store_true',
                      help='test output verbosity (when running with -t)')
    (options, args) = parser.parse_args()

    if options.run_tests:
        unittest.main(argv=sys.argv[:1], verbosity=not options.quiet and 2 or 0)

    if len(args) == 1:
        if options.aes and args[0].endswith('.e'):
            print('AES selected, but appears to use blowfish extension.')
            if raw_input('Use blowfish instead? (Yn) ') != 'n':
                options.aes = False
        elif not options.aes and args[0].endswith('.ae'):
            print('AES not selected, but appears to use AES extension.')
            if raw_input('Use AES instead? (Yn) ') != 'n':
                options.aes = True

        ext = '.ae' if options.aes else '.e'
        if options.encrypt:
            default = '%s%s' % (args[0], ext)
        else:
            default = args[0].rstrip(ext)
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

    cipher_type = CIPHER_AES if options.aes else CIPHER_BLOWFISH
    if options.encrypt:
        encrypt_file(infile, outfile, key, cipher_type=cipher_type)
    else:
        decrypt_file(infile, outfile, key, cipher_type=cipher_type)
