heartBleedTester
================

Test for SSL heartbleed vulnerability

##Usage
`heartBleed.py <network> [network2] [network3] ...`

###Options:
    -h, --help         show this help message and exit
    -o                 Output the data when the server is vulnerable.
    -f OUTTOFILE       Output the data to a file when the server is vulnerable.
    --threads=THREADS  Thread number, defaut is 5.

##Example:
    python heartBleed.py 127.0.0.1
    \>\>\>The domain 127.0.0.1 is vulnerable!

    python heartBleed.py google.com
    \>\>\>The domain google.com is NOT vulnerable.

##Reference
[heartbleed-masstest](https://github.com/musalbas/heartbleed-masstest)
[RFC6520](https://tools.ietf.org/html/rfc6520)

