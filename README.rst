=========
vmod_hmac
=========

------------------------
Varnish HMAC Hash Module
------------------------

:Author: Ryusuke SEKIYAMA
:Date: 2012-07-04
:Version: 1.0
:Manual section: 3

SYNOPSIS
========

import hmac;

DESCRIPTION
===========

HMAC-SHA1 / HMAC-SHA256 function vmod using OpenSSL.

Implements the traditional Hello World as a vmod.

FUNCTIONS
=========

sha1_base64
-----------

Prototype
        ::

                sha1_base64(STRING key, STRING data)
Return value
	STRING
Description
	Returns a Base64 encoded keyed hash value using the HMAC-SHA1 method.
Example
        ::

                set resp.http.hmac = hmac.sha1_base64("Hello", "World");

sha1_hex
--------

Prototype
        ::

                sha1_hex(STRING key, STRING data)
Return value
	STRING
Description
	Returns a hexadecimal encoded keyed hash value using the HMAC-SHA1 method.
Example
        ::

                set resp.http.hmac = hmac.sha1_hex("Hello", "World");

sha256_base64
-------------

Prototype
        ::

                sha256_base64(STRING key, STRING data)
Return value
	STRING
Description
	Returns a Base64 encoded keyed hash value using the HMAC-SHA256 method.
Example
        ::

                set resp.http.hmac = hmac.sha256_base64("Hello", "World");

sha256_hex
----------

Prototype
        ::

                sha256_hex(STRING key, STRING data)
Return value
	STRING
Description
	Returns a hexadecimal encoded keyed hash value using the HMAC-SHA256 method.
Example
        ::

                set resp.http.hmac = hmac.sha256_hex("Hello", "World");

INSTALLATION
============

This is a HMAC-SHA1 / HMAC-SHA256 function vmod using OpenSSL.

The source tree is based on autotools to configure the building, and
does also have the necessary bits in place to do functional unit tests
using the varnishtest tool.

Usage::

 ./configure VARNISHSRC=DIR [VMODDIR=DIR] [--with-openssl-dir=DIR]

`VARNISHSRC` is the directory of the Varnish source tree for which to
compile your vmod. Both the `VARNISHSRC` and `VARNISHSRC/include`
will be added to the include search paths for your module.

Optionally you can also set the vmod install directory by adding
`VMODDIR=DIR` (defaults to the pkg-config discovered directory from your
Varnish installation).

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`
* make check - runs the unit tests in ``src/tests/*.vtc``

In your VCL you could then use this vmod along the following lines::
        
        import hmac;

        sub vcl_deliver {
                # This sets resp.http.hmac to "Hello, World"
                set resp.http.hmac = hmac.sha1_base64("Hello", "World");
        }

HISTORY
=======

This manual page was released as part of the libvmod-hmac package.

COPYRIGHT
=========

This document is licensed under the same license as the
libvmod-hmac project. See LICENSE for details.

* Copyright (c) 2012 Ryusuke SEKIYAMA
