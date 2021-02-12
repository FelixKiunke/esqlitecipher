%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @author Felix Kiunke <dev@fkiunke.de>
%% @copyright 2011 - 2021 Maas-Maarten Zeeman, Felix Kiunke
%% @version 1.2.0

%% @doc Erlang API for sqlite3 and sqlcipher databases.
%% This is an adaptation of Maas-Maarten Zeeman's esqlite package for
%% <a href="https://www.zetetic.net/sqlcipher/">sqlcipher</a> encrypted sqlite3
%% databases.
%%
%% All functions (except {@link is_encrypted/1}) take an optional `Timeout'
%% argument. The default value for this timeout is 5 seconds (`5000').
%%
%% To open or create a database, use either {@link open/2} or
%% {@link open_encrypted/3}. These return a database connection that can be used
%% in the other functions and should be closed afterwards using {@link close/2}.

%% Copyright 2011 - 2021 Maas-Maarten Zeeman, Felix Kiunke
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(esqlcipher).
-author("Maas-Maarten Zeeman <mmzeeman@xs4all.nl>").

%% higher-level export
-export([open/1, open/2,
         open_encrypted/2, open_encrypted/3,
         close/1, close/2,
         is_encrypted/1,
         rekey/2, rekey/3,
         exec/2, exec/3, exec/4,
         insert/2, insert/3,
         prepare/2, prepare/3,
         bind/2, bind/3,
         prepare_bind/3, prepare_bind/4,
         reset/1, reset/2,
         run/1, run/2,
         fetch_one/1, fetch_one/2,
         fetch_chunk/2, fetch_chunk/3,
         fetch_all/1, fetch_all/2, fetch_all/3,
         changes/1, changes/2,
         column_names/1, column_names/2,
         column_types/1, column_types/2,
         get_autocommit/1, get_autocommit/2,
         set_update_hook/2, set_update_hook/3,

         q/2, q/3, q/4,
         map/3, map/4, map/5,
         foreach/3, foreach/4, foreach/5]).

-define(DEFAULT_TIMEOUT, 5000).
-define(DEFAULT_CHUNK_SIZE, 5000).
%% How many times to retry fetching from a busy database. 0 = fail immediately when busy
-define(MAX_TRIES, 5).

-type connection() :: {connection, pid(), plaintext | encrypted}.
%% Database connection type.
%% Returned by {@link open/2} and {@link open_encrypted/3}.

-type statement() :: {statement, term(), connection()}.
%% Prepared statement type.
%% Returned by {@link prepare/3} or {@link prepare_bind/4}.

-type sqlite_error() :: {error, {atom(), string()}}.
%% Error return type.
%% Contains an error id atom and a reason/error message.

-type sql() :: iodata().
%% SQL string type.

-type row() :: tuple().
%% SQL row type.

-type sql_value() :: number() | atom() | iodata() | {blob, iodata()}.
%% SQL value type.

-type map_function(ReturnType) :: fun((Row :: row()) -> ReturnType) | fun((ColNames :: tuple(), Row :: row()) -> ReturnType).
%% Type of functions used in {@link map/5}.

-type foreach_function() :: fun((Row :: row()) -> any()) | fun((ColNames :: tuple(), Row :: row()) -> any()).
%% Type of functions used in {@link foreach/5}.



%% @equiv open(Filename, 5000)
-spec open(string()) ->  {ok, connection()} | sqlite_error().
open(Filename) ->
    open(Filename, ?DEFAULT_TIMEOUT).

%% @doc Open an unencrypted database connection.
%% If `Filename' doesn't exist, it will be created. You can also open an
%% in-memory database that will be destroyed after closing by giving `:memory:'
%% as the Filename. <a href="https://www.sqlite.org/uri.html">URI filenames</a>
%% are allowed as well.
%%
%% The database will be checked by testing whether `sqlite_master' is readable.
%% Unreadable, corrupted or encrypted databases will return an error of the form
%% `{error, {baddb, _}}'.
%%
%% Since sqlcipher is just sqlite3 under the hood, these unencrypted databases
%% are fully compatible with sqlite3.
-spec open(string(), timeout()) -> {ok, connection()} | sqlite_error().
open(Filename, Timeout) ->
    {ok, Connection} = esqlcipher_nif:start(),

    Ref = make_ref(),
    ok = esqlcipher_nif:open(Connection, Ref, self(), Filename),
    case receive_answer(Ref, Timeout) of
        ok ->
            Conn = {connection, Connection, plaintext},
            case exec("SELECT * FROM main.sqlite_master LIMIT 0;", Conn, Timeout) of
                {error, _} ->
                    ok = close(Conn),
                    {error, {baddb, "file is encrypted or not a valid database"}};
                ok ->
                    {ok, Conn}
            end;
        {error, _Msg} = Error ->
            Error
    end.


%% @equiv open_encrypted(Filename, Key, 5000)
-spec open_encrypted(string(), string()) -> {ok, connection()} | sqlite_error().
open_encrypted(Filename, Key) ->
    open_encrypted(Filename, Key, ?DEFAULT_TIMEOUT).

%% @doc Open an encrypted database connection.
%% If `Filename' doesn't exist, it will be created.
%%
%% The database will be checked by testing whether `sqlite_master' is readable.
%% Unreadable or corrupted databases as well as an incorrect `Key' will
%% return an error of the form `{error, {baddb, _}}'.
%%
%% Normally, the actual database key will be derived from `Key' using PBKDF2
%% key derivation by sqlcipher. However, it's possible to specify a raw byte
%% sequence as a key. This key has to be hex-encoded and can be used by passing
%% ``"x'A0B1C2(...)D3E4F5'"'' using a 64 character hex string for a resulting
%% 32 byte key (256 bits). Finally, an exact database salt can be specified as
%% well by passing a 96 character hex string (the last 32 characters will be
%% used as the salt). If the salt is not explicitly provided, it will be
%% generated randomly and stored in the first 16 bytes of the database.
%% 
%% Please refer to the
%% <a href="https://www.zetetic.net/sqlcipher/sqlcipher-api/#key">sqlcipher
%% documentation</a> for further information about the generation and usage of
%% encryption keys.
-spec open_encrypted(string(), string(), timeout()) -> {ok, connection()} | sqlite_error().
open_encrypted(Filename, Key, Timeout) ->
    {ok, Connection} = esqlcipher_nif:start(),

    Ref = make_ref(),
    ok = esqlcipher_nif:open(Connection, Ref, self(), Filename),
    case receive_answer(Ref, Timeout) of
        ok ->
            Conn = {connection, Connection, encrypted},
            case key(Key, Conn, Timeout) of
                {error, _} = Error ->
                    ok = close(Conn),
                    Error;
                ok ->
                    {ok, Conn}
            end;
        {error, _Msg} = Error ->
            Error
    end.


%% @equiv close(Connection, 5000)
-spec close(connection()) -> ok | sqlite_error().
close(Connection) ->
    close(Connection, ?DEFAULT_TIMEOUT).

%% @doc Close the database connection.
-spec close(Connection :: connection(), timeout()) -> ok | sqlite_error().
close({connection, Connection, _}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:close(Connection, Ref, self()),
    receive_answer(Ref, Timeout).


%% @doc Whether a database is encrypted.
%% Returns true if the database connection is to an encrypted database, false
%% if it's a plaintext database
-spec is_encrypted(Connection :: connection()) -> boolean().
is_encrypted({connection, _, encrypted}) -> true;
is_encrypted({connection, _, plaintext}) -> false.


%% @doc Unlock database and test whether the key is correct.
%% Must be called before the database is written to.
%% @private
-spec key(string(), connection(), timeout()) -> ok | sqlite_error().
key(Key, {connection, Conn, encrypted}=Connection, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:key(Conn, Ref, self(), Key),
    case receive_answer(Ref, Timeout) of
        ok ->
            % Test whether the given key was correct. If not, this will give an error
            case exec("SELECT * FROM main.sqlite_master LIMIT 0;", Connection, Timeout) of
                {error, {notadb, _}} ->
                    {error, {baddb, "invalid key or file is not a valid database"}};
                {error, _} = Error ->
                    Error;
                ok -> ok
            end;
        {error, _} -> error
    end.


%% @equiv rekey(Key, Connection, 5000)
-spec rekey(string(), connection()) -> ok | sqlite_error().
rekey(Key, Connection) ->
    rekey(Key, Connection, ?DEFAULT_TIMEOUT).

%% @doc Change the database key.
%% This function cannot be used to encrypt an unencrypted database and will
%% return an error `{error, {rekey_plaintext, _}}' if called on one.
%%
%% @see open_encrypted/3
-spec rekey(string(), Connection :: connection(), timeout()) ->  ok | sqlite_error().
rekey(_, {connection, _, plaintext}, _Timeout) ->
    {error, {rekey_plaintext, "cannot rekey an unencrypted database"}};
rekey(Key, {connection, Conn, encrypted}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:rekey(Conn, Ref, self(), Key),
    receive_answer(Ref, Timeout).


%% @equiv set_update_hook(Pid, Connection, 5000)
-spec set_update_hook(pid(), connection()) -> ok | sqlite_error().
set_update_hook(Pid, Connection) ->
    set_update_hook(Pid, Connection, ?DEFAULT_TIMEOUT).

%% @doc Subscribe to notifications for row updates, insertions and deletions.
%% Messages will come in the shape of `{Action, Table :: string(), Id :: integer()}',
%% where `Action' will be either `insert', `update' or `delete' and `Id' will be
%% the affected row id (i.e. the `INTEGER PRIMARY KEY' if the table has one).
-spec set_update_hook(pid(), connection(), timeout()) -> ok | sqlite_error().
set_update_hook(Pid, {connection, Connection, _}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:set_update_hook(Connection, Ref, self(), Pid),
    receive_answer(Ref, Timeout).


%% @equiv exec(Sql, Connection, 5000)
-spec exec(sql(), connection()) -> ok | sqlite_error().
exec(Sql, Connection) ->
    exec(Sql, Connection, ?DEFAULT_TIMEOUT).

%% @doc Execute (simple or prepared) SQL statement without returning anything.
%%
%% The second form of invocation (with `Params') is equivalent to
%% {@link exec/4. `exec(Sql, Params, Connection, 5000)'}.
-spec exec(sql(), Connection :: connection(), timeout()) -> ok | sqlite_error()
        ; (sql(), [_], connection()) -> ok | sqlite_error().
exec(Sql, {connection, Connection, _}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:exec(Connection, Ref, self(), Sql),
    receive_answer(Ref, Timeout);
exec(Sql, Params, {connection, _, _}=Connection) when is_list(Params) ->
    exec(Sql, Params, Connection, ?DEFAULT_TIMEOUT).

%% @doc Execute prepared SQL statement without returning anything.
%% @param Params values that are bound to the SQL statement
-spec exec(sql(), list(term()), connection(), timeout()) -> ok | sqlite_error().
exec(Sql, Params, {connection, _, _}=Connection, Timeout) when is_list(Params) ->
    {ok, Statement} = prepare_bind(Sql, Params, Connection, Timeout),
    run(Statement, Timeout).


%% @equiv insert(Sql, Connection, 5000)
-spec insert(sql(), connection()) -> {ok, integer()} |  sqlite_error().
insert(Sql, Connection) ->
    insert(Sql, Connection, ?DEFAULT_TIMEOUT).

%% @doc Insert records, returns the last inserted rowid.
%% `Sql' can be any `INSERT' statement. If the table has a column of type
%% `INTEGER PRIMARY KEY', the returned rowid will equal that primary key.
%% See also the sqlite3 docs for
%% <a href="https://sqlite.org/c3ref/last_insert_rowid.html">sqlite3_last_insert_rowid</a>.
-spec insert(sql(), Connection :: connection(), timeout()) -> {ok, integer()} | sqlite_error().
insert(Sql, {connection, Connection, _}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:insert(Connection, Ref, self(), Sql),
    receive_answer(Ref, Timeout).


%% @equiv prepare(Sql, Connection, Timeout)
-spec prepare(sql(), connection()) -> {ok, statement()} | sqlite_error().
prepare(Sql, Connection) ->
    prepare(Sql, Connection, ?DEFAULT_TIMEOUT).

%% @doc Prepare (i.e. compile) an SQL statement.
%% Value placeholder can then be bound using {@link bind/3}. Or, you can do both
%% in one step using {@link prepare_bind/4}!
-spec prepare(sql(), connection(), timeout()) -> {ok, statement()} | sqlite_error().
prepare(Sql, {connection, Connection, _}=C, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:prepare(Connection, Ref, self(), Sql),
    case receive_answer(Ref, Timeout) of
        {ok, Stmt} -> {ok, {statement, Stmt, C}};
        Else -> Else
    end.


%% @equiv bind(Statement, Args, 5000)
-spec bind(statement(), [sql_value()]) -> ok | sqlite_error().
bind(Statement, Args) ->
    bind(Statement, Args, ?DEFAULT_TIMEOUT).

%% @doc Bind values to a prepared statement created by {@link prepare/3}.
%% Note that you can also use {@link prepare_bind/4} to prepare and bind a
%% statement in one step.
-spec bind(Statement :: statement(), [sql_value()], timeout()) -> ok | sqlite_error().
bind({statement, Stmt, {connection, Conn, _}}, Args, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:bind(Conn, Stmt, Ref, self(), Args),
    receive_answer(Ref, Timeout).


%% @equiv prepare_bind(Sql, Args, Connection, 5000)
-spec prepare_bind(sql(), [sql_value()], connection()) -> {ok, statement()} | sqlite_error().
prepare_bind(Sql, Args, Connection) ->
    prepare_bind(Sql, Args, Connection, ?DEFAULT_TIMEOUT).

%% @doc Prepare an SQL statement and bind values to it.
%% This is simply {@link prepare/3} and {@link bind/3} in a single step.
-spec prepare_bind(sql(), [sql_value()], connection(), timeout()) -> {ok, statement()} | sqlite_error().
prepare_bind(Sql, [], {connection, _, _}=Connection, Timeout) ->
    prepare(Sql, Connection, Timeout);
prepare_bind(Sql, Args, {connection, _, _}=Connection, Timeout) ->
    case prepare(Sql, Connection, Timeout) of
        {ok, Statement} ->
            case bind(Statement, Args, Timeout) of
                ok -> {ok, Statement};
                {error, _} = Error -> Error
            end;
        {error, _} = Error ->
            Error
    end.


%% @equiv reset(Statement, 5000)
-spec reset(statement()) -> ok | sqlite_error().
reset(Statement) ->
    reset(Statement, ?DEFAULT_TIMEOUT).

%% @doc Reset the prepared statement back to its initial state.
-spec reset(Statement :: statement(), timeout()) -> ok | sqlite_error().
reset({statement, Stmt, {connection, Conn, _}}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:reset(Conn, Stmt, Ref, self()),
    receive_answer(Ref, Timeout).


%% @doc attempt to fetch multiple results in one call.
%% Returns rows in reverse order
%% @private
-spec multi_step(statement(), pos_integer(), timeout()) ->
                {rows, list(tuple())} |
                {'$busy', list(tuple())} |
                {'$done', list(tuple())} |
                {error, term()}.
multi_step({statement, Stmt, {connection, Conn, _}}, ChunkSize, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:multi_step(Conn, Stmt, ChunkSize, Ref, self()),
    receive_answer(Ref, Timeout).


%% @doc retry `multi_step' a number of times if the database is busy.
%% Returns rows in reverse order
%% @private
-spec try_multi_step(statement(), pos_integer(), [tuple()], non_neg_integer(), timeout()) ->
    {rows, [tuple()]} | {'$done', [tuple()]} | sqlite_error().
try_multi_step(_Statement, _ChunkSize, _Rest, Tries, _Timeout) when Tries > ?MAX_TRIES ->
    {error, {busy, "database is busy"}};
try_multi_step(Statement, ChunkSize, Rest, Tries, Timeout) ->
    case multi_step(Statement, ChunkSize, Timeout) of
        {'$busy', Rows} ->
            % NB: It's possible that the database only becomes busy after a number
            % of rows have already been fetched.
            % Exponential backoff:
            timer:sleep(50 + math:pow(2, Tries) * 10),
            try_multi_step(Statement, ChunkSize, Rows ++ Rest, Tries + 1, Timeout);
        {rows, Rows} ->
            {rows, Rows ++ Rest};
        {'$done', Rows} ->
            {'$done', Rows ++ Rest};
        Else -> Else
    end.

%% @equiv fetch_chunk(Statement, ChunkSize, 5000)
-spec fetch_chunk(statement(), pos_integer()) -> {rows | '$done', [row()]} | sqlite_error().
fetch_chunk(Statement, ChunkSize) ->
    fetch_chunk(Statement, ChunkSize, ?DEFAULT_TIMEOUT).

%% @doc fetch a number of rows.
%% Can be called multiple times to fetch more rows.
%% @param Statement a prepared sql statement created by {@link prepare/3} or {@link prepare_bind/4}
%% @param ChunkSize is a number of rows to be read from sqlite and sent to erlang
%% @param Timeout timeout for the whole operation. Might need to be increased for very large chunks
%% @returns `{rows, [...]}' if more rows exist but where not fetched due to the `ChunkSize' limit;
%%   ``{'$done', [...]}'' if these where the last rows
-spec fetch_chunk(statement(), pos_integer(), timeout()) ->
    {rows | '$done', [row()]} | sqlite_error().
fetch_chunk(Statement, ChunkSize, Timeout) ->
    try_multi_step(Statement, ChunkSize, [], 0, Timeout).


%% @equiv fetch_one(Statement, 5000)
-spec fetch_one(statement()) -> ok | {ok, row()} | sqlite_error().
fetch_one(Statement) ->
    fetch_one(Statement, ?DEFAULT_TIMEOUT).

%% @doc fetch exactly one row of results. Returns `ok' if the result is empty.
%% @param Statement a prepared sql statement created by {@link prepare/3} or {@link prepare_bind/4}
%% @returns `{ok, X}' if the statement was executed successfully where `X' is
%%   either a row in the shape of a tuple or `nil' if no rows where returned
-spec fetch_one(statement(), timeout()) -> ok | {ok, row()} | sqlite_error().
fetch_one(Statement, Timeout) ->
    case fetch_chunk(Statement, 1, Timeout) of
        {error, _} = Error -> Error;
        {'$done', []} -> {ok, nil};
        {rows, [Row]} -> {ok, Row}
    end.


%% @equiv run(Statement, 5000)
-spec run(statement()) -> ok | sqlite_error().
run(Statement) ->
    run(Statement, ?DEFAULT_TIMEOUT).

%% @doc run a prepared statement, ignoring any possible results.
%% If you want to ensure that a query finishes correctly, returning exactly zero
%% rows, use:
%%
%% `{ok, nil} = {@link fetch_one/2. fetch_one}(Statement, Timeout)'
%%
%% @returns `ok' if the query finishes without an error,
%%   whether or not it returns any rows.
-spec run(statement(), timeout()) -> ok | sqlite_error().
run(Statement, Timeout) ->
    case fetch_one(Statement, Timeout) of
        {ok, _} -> ok;
        Else -> Else
    end.


%% @equiv fetch_all(Statement, 5000, 5000)
-spec fetch_all(statement()) ->
                      list(tuple()) |
                      {error, term()}.
fetch_all(Statement) ->
    fetch_all(Statement, ?DEFAULT_CHUNK_SIZE, ?DEFAULT_TIMEOUT).

%% @equiv fetch_all(Statement, ChunkSize, 5000)
-spec fetch_all(statement(), pos_integer()) ->
                      list(tuple()) |
                      {error, term()}.
fetch_all(Statement, ChunkSize) ->
    fetch_all(Statement, ChunkSize, ?DEFAULT_TIMEOUT).

%% @doc Fetch all records
%% @param Statement a prepared sql statement created by {@link prepare/3} or {@link prepare_bind/4}
%% @param ChunkSize is a number of rows to be read from sqlite and sent to erlang in one bulk
%%        Decrease this value if rows are heavy. Default value is 5000 (`DEFAULT_CHUNK_SIZE').
%% @param Timeout is timeout per each request of one bulk
-spec fetch_all(statement(), pos_integer(), timeout()) -> [row()] | sqlite_error().
fetch_all(Statement, ChunkSize, Timeout) ->
    case fetch_all_internal(Statement, ChunkSize, [], Timeout) of
        {'$done', Rows} -> lists:reverse(Rows);
        {error, _} = Error -> Error
    end.

%% @doc Fetches all rows in chunk. Rows are returned in reverse order.
%% @private
-spec fetch_all_internal(statement(), pos_integer(), [row()], timeout()) ->
    {'$done', [row()]} | sqlite_error().
fetch_all_internal(Statement, ChunkSize, Rest, Timeout) ->
    case try_multi_step(Statement, ChunkSize, Rest, 0, Timeout) of
        {rows, Rows} -> fetch_all_internal(Statement, ChunkSize, Rows, Timeout);
        Else -> Else
    end.


%% @equiv changes(Connection, 5000)
changes(Connection) ->
    changes(Connection, ?DEFAULT_TIMEOUT).

%% @doc Return the number of affected rows of the last statement.
-spec changes(Connection :: connection(), timeout()) -> {ok, integer()} | sqlite_error().
changes({connection, Connection, _}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:changes(Connection, Ref, self()),
    receive_answer(Ref, Timeout).


%% @equiv column_names(Statement, 5000)
-spec column_names(statement()) -> tuple().
column_names(Statement) ->
    column_names(Statement, ?DEFAULT_TIMEOUT).

%% @doc Return the column names of the prepared statement.
-spec column_names(Statement :: statement(), timeout()) -> tuple().
column_names({statement, Stmt, {connection, Conn, _}}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:column_names(Conn, Stmt, Ref, self()),
    {ok, ColumnNames} = receive_answer(Ref, Timeout),
    ColumnNames.


%% @equiv column_types(Statement, 5000)
-spec column_types(statement()) -> tuple().
column_types(Stmt) ->
    column_types(Stmt, ?DEFAULT_TIMEOUT).

%% @doc Return the declared column types of the prepared statement.
%% Note that since sqlite3 is dynamically typed, actual column values need not
%% necessarily conform to the declared type
-spec column_types(statement(), timeout()) -> tuple().
column_types({statement, Stmt, {connection, Conn, _}}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:column_types(Conn, Stmt, Ref, self()),
    {ok, ColumnTypes} = receive_answer(Ref, Timeout),
    ColumnTypes.


%% @equiv get_autocommit(Connection, 5000)
-spec get_autocommit(connection()) -> boolean() | sqlite_error().
get_autocommit(Connection) ->
    get_autocommit(Connection, ?DEFAULT_TIMEOUT).

%% @doc Returns whether the database is in <a href="https://sqlite.org/c3ref/get_autocommit.html">autocommit mode</a>.
%% Autocommit is normally enabled, except within transactions.
-spec get_autocommit(Connection :: connection(), timeout()) -> boolean() | sqlite_error().
get_autocommit({connection, Connection, _}, Timeout) ->
    Ref = make_ref(),
    ok = esqlcipher_nif:get_autocommit(Connection, Ref, self()),
    receive_answer(Ref, Timeout).


%% @equiv q(Sql, [], Connection, 5000)
%% @throws sqlite_error()
-spec q(sql(), connection()) -> [tuple()].
q(Sql, Connection) ->
    q(Sql, [], Connection, ?DEFAULT_TIMEOUT).

%% @equiv q(Sql, Args, Connection, 5000)
%% @throws sqlite_error()
-spec q(sql(), [sql_value()], connection()) -> [tuple()].
q(Sql, Args, Connection) ->
    q(Sql, Args, Connection, ?DEFAULT_TIMEOUT).

%% @doc Prepare statement, bind args and return a list with tuples as result.
%% Errors are thrown, not returned.
%% @throws sqlite_error()
-spec q(sql(), [sql_value()], connection(), timeout()) -> [tuple()].
q(Sql, Args, Connection, Timeout) ->
    case prepare_bind(Sql, Args, Connection, Timeout) of
        {ok, Statement} ->
            case fetch_all(Statement, ?DEFAULT_CHUNK_SIZE, Timeout) of
                {error, _} = Error ->
                    throw(Error);
                Res ->
                    Res
            end;
        {error, _} = Error ->
            throw(Error)
    end.


%% @equiv map(F, Sql, [], Connection, 5000)
%% @throws sqlite_error()
-spec map(map_function(Type), sql(), connection()) -> [Type].
map(F, Sql, {connection, _, _} = Connection) ->
    map(F, Sql, [], Connection, ?DEFAULT_TIMEOUT).

%% @equiv map(F, Sql, [], Connection, 5000)
%% @throws sqlite_error()
-spec map(map_function(Type), sql(), [sql_value()], connection()) -> [Type].
map(F, Sql, Args, Connection) ->
    map(F, Sql, Args, Connection, ?DEFAULT_TIMEOUT).

%% @doc Map over all rows returned by the SQL query `Sql'.
%% @param A function that takes either one parameter (a row tuple) or two
%%   (a column name tuple and a row tuple) and returns any kind of value
%% @param Sql an SQL query
%% @param Args values that are bound to `Sql'
%% @throws sqlite_error()
-spec map(map_function(Type), sql(), [sql_value()], connection(), timeout()) -> [Type].
map(F, Sql, Args, Connection, Timeout) ->
    case prepare_bind(Sql, Args, Connection, Timeout) of
        {ok, Statement} ->
            {ok, ColumnNames} = column_names(Statement, Timeout),
            map_s(F, Statement, ColumnNames, Timeout);
        {error, _Msg} = Error ->
            throw(Error)
    end.


%% @doc Map function over statement results
%% @private
-spec map_s(map_function(Type), statement(), tuple(), timeout()) -> [Type].
map_s(F, Statement, ColNames, Timeout) when is_function(F, 1) ->
    case fetch_one(Statement, Timeout) of
        ok -> [];
        {ok, Row} -> [F(Row) | map_s(F, Statement, ColNames, Timeout)];
        {error, _} = Error -> throw(Error)
    end;
map_s(F, Statement, ColNames, Timeout) when is_function(F, 2) ->
    case fetch_one(Statement, Timeout) of
        ok -> [];
        {ok, Row} -> [F(ColNames, Row) | map_s(F, ColNames, Statement, Timeout)];
        {error, _} = Error -> throw(Error)
    end.



%% @equiv foreach(F, Sql, [], Connection, 5000)
%% @throws sqlite_error()
-spec foreach(foreach_function(), sql(), connection()) -> ok.
foreach(F, Sql, {connection, _, _} = Connection) ->
    foreach(F, Sql, [], Connection, ?DEFAULT_TIMEOUT).

%% @equiv foreach(F, Sql, Args, Connection, 5000)
%% @throws sqlite_error()
-spec foreach(foreach_function(), sql(), [sql_value()], connection()) -> ok.
foreach(F, Sql, Args, Connection) ->
    foreach(F, Sql, Args, Connection, ?DEFAULT_TIMEOUT).


%% @doc Execute a function for all rows returned by the SQL query `Sql'.
%% @param A function that takes either one parameter (a row tuple) or two
%%   (a column name tuple and a row tuple). Return values are ignored.
%% @param Sql an SQL query
%% @param Args values that are bound to `Sql'
%% @throws sqlite_error()
-spec foreach(foreach_function(), sql(), [sql_value()], connection(), timeout()) -> ok.
foreach(F, Sql, Args, Connection, Timeout) ->
    case prepare_bind(Sql, Args, Connection, Timeout) of
        {ok, Statement} ->
            {ok, ColumnNames} = column_names(Statement, Timeout),
            ok = foreach_s(F, Statement, ColumnNames, Timeout);
        {error, _Msg} = Error ->
            throw(Error)
    end.

%% @doc Run function for each row
%% @private
-spec foreach_s(foreach_function(), statement(), tuple(), timeout()) -> ok.
foreach_s(F, Statement, ColNames, Timeout) when is_function(F, 1) ->
    case fetch_one(Statement, Timeout) of
        ok -> ok;
        {ok, Row} -> 
            F(Row),
            foreach_s(F, Statement, ColNames, Timeout);
        {error, _} = Error -> throw(Error)
    end;
foreach_s(F, Statement, ColNames, Timeout) when is_function(F, 2) ->
    case fetch_one(Statement, Timeout) of
        ok -> ok;
        {ok, Row} -> 
            F(ColNames, Row),
            foreach_s(F, ColNames, Statement, Timeout);
        {error, _} = Error -> throw(Error)
    end.


%% @doc Wait for an answer for the request referred as `Ref'.
%% @private
%-spec receive_answer(reference(), )
receive_answer(Ref, Timeout) ->
    Start = os:timestamp(),
    receive
        {esqlcipher, Ref, Resp} ->
            Resp;
        {esqlcipher, _, _}=StaleAnswer ->
            error_logger:warning_msg("Esqlcipher: Ignoring stale answer ~p~n", [StaleAnswer]),
            PassedMics = timer:now_diff(os:timestamp(), Start) div 1000,
            NewTimeout = case Timeout - PassedMics of
                             Passed when Passed < 0 -> 0;
                             TO -> TO
                         end,
            receive_answer(Ref, NewTimeout)
    after Timeout ->
            throw({error, timeout, Ref})
    end.
