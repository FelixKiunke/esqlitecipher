[![Build Status](https://app.travis-ci.com/FelixKiunke/esqlcipher.svg?branch=master)](https://app.travis-ci.com/FelixKiunke/esqlcipher)
[![Hex.pm](https://img.shields.io/hexpm/v/esqlcipher.svg)](https://hex.pm/packages/esqlcipher)
[![Hex.pm](https://img.shields.io/hexpm/dt/esqlcipher.svg)](https://hex.pm/packages/esqlcipher)

Esqlcipher
==========

An Erlang nif library for [sqlcipher](https://github.com/sqlcipher/sqlcipher).

Introduction
------------

This library allows you to use the [sqlcipher](https://github.com/sqlcipher/sqlcipher)
library based on the fantastic [sqlite3](https://www.sqlite.org/index.html)
engine from erlang. The library is implemented as a nif library, which allows
for the fastest access to a sqlite database. This can be risky, as a bug
in the nif library or the sqlite database can crash the entire Erlang
VM. If you do not want to take this risk, it is always possible to
access the sqlite nif from a separate erlang node.

Special care has been taken not to block the scheduler of the calling
process. This is done by handling all commands from erlang within a
lightweight thread. The erlang scheduler will get control back when
the command has been added to the command-queue of the thread.

Versions
--------

The library currently uses Sqlcipher version `4.5.0`, which is based on sqlite
version `3.36.0` compiled using the following compile-time options:

```
-DSQLITE_DQS=0 -DSQLITE_HAS_CODEC -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1 -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_OMIT_DEPRECATED -DSQLITE_TEMPSTORE=2 -DSQLITE_THREADSAFE=1 -DSQLITE_USE_URI -DSQLITE_ENABLE_FTS4 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_FTS3_PARENTHESIS -DSQLITE_ENABLE_JSON1 -DSQLITE_ENABLE_MATH_FUNCTIONS
```

Caveats
-------

The interface could probably use some polishig. Sqlcipher mostly this works
exactly like SQLite3, except for the crypto stuff. However, the Sqlcipher
included in this is built using some breaking compile time options such as
`SQLITE_DQS = 0` (see [here](https://www.sqlite.org/compile.html#recommended_compile_time_options)).
This means that string literals in SQL commands *must* use single quotes.
For instance, this:
```SQL
INSERT INTO test_table VALUES('hello', 11);
```
works while the following will not do what you would expect:
```SQL
# this is wrong!
INSERT INTO test_table VALUES("hello", 11);
```

See `rebar.config.script` for all compile options that were set!


TODO (Incomplete list)
----------------------

- Better testing of encryption
- Primitives that support named databases (i.e. `sqlite3_key_v2()`)
- Configuration options (HMAC, PBKDF2 iterations, salts, page sizes, ...)
- Testing on other platforms
- ...


On the Author(s)
----------------

This version is derived from Maas-Maarten Zeeman’s Erlang sqlite
library [esqlite](https://github.com/mmzeeman/esqlite).
I (Felix Kiunke) merely made some smaller amendments to provide
support for sqlcipher, a library that provides encryption for sqlite
databases.