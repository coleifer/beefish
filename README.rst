beefish
=======

Easy file encryption using pycrypto

.. image:: http://media.charlesleifer.com/blog/photos/beefish.jpg


installing
----------

::

    pip install beefish pycrypto

Alternatively::

    pip install -e git+git://github.com/coleifer/beefish.git#egg=beefish

Dependencies:

* `pycrypto <https://www.dlitz.net/software/pycrypto/>`_


command-line options
--------------------

Usage::

    beefish.py [-tkedaq] in_file [out_file]

* ``-e`` - encrypt the provided ``in_file`` and write to ``out_file``
* ``-d`` - decrypt the provided ``in_file`` and write to ``out_file``
* ``-k`` - specify password as command-line argument (if unspecified you will
  be securely prompted).
* ``-a`` - use AES-256 instead of the default "Blowfish" cipher.
* ``-t`` - run test suite
* ``-q`` - quiet mode (controls verbosity of test output).


examples
--------

beefish can be used to encrypt and decrypt file-like objects::

    from beefish import encrypt, decrypt

    # encrypting
    with open('secrets.txt') as fh:
        with open('secrets.enc', 'wb') as out_fh:
            encrypt(fh, out_fh, 'secret p@ssword')

    # decrypting
    with open('secrets.enc') as fh:
        with open('secrets.dec', 'wb') as out_fh:
            decrypt(fh, out_fh, 'secret p@ssword')

you can use a shortcut if you like::

    # encrypting
    encrypt_file('secrets.txt', 'secrets.enc', 'p@ssword')

    # decrypting
    decrypt_file('secrets.enc', 'secrets.dec', 'p@ssword')


you can use it from the command-line::

    beefish.py -e secrets.txt secrets.enc
    beefish.py -d secrets.enc secrets.dec

to use AES-256 cipher instead of the default, which is blowfish:

    beefish.py -a -e secrets.txt
    beefish.py -a -d secrets.encrypted
