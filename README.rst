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


usage
-----

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
