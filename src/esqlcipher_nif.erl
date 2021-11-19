%% @author Maas-Maarten Zeeman <mmzeeman@xs4all.nl>
%% @author Felix Kiunke <dev@fkiunke.de>
%% @copyright 2011 - 2021 Maas-Maarten Zeeman, Felix Kiunke
%% @version 2.0.0-rc.3

%% @doc Low level erlang API for sqlite3 databases.
%% The actual work happens in an asynchronous low level thread that is started
%% using {@link start/0}. These functions are implemented in native C.
%% All functions return immediately; results are sent as a message when ready.

%% Copyright 2011 - 2017 Maas-Maarten Zeeman
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

-module(esqlcipher_nif).
-author("Maas-Maarten Zeeman <mmzeeman@xs4all.nl>").
-author("Felix Kiunke <dev@fkiunke.de>").

%% low-level exports
-export([start/0,
         open/4,
         close/3,
         key/4,
         rekey/4,
         exec/4,
         insert/4,
         prepare/4,
         bind/5,
         multi_step/5,
         reset/5,
         changes/3,
         column_names/4,
         column_types/4,
         get_autocommit/3,
         set_update_hook/4
        ]).

-on_load(init/0).

-type connection() :: reference().
-type statement() :: reference().

-type sql() :: iodata().
%% SQL string type.

-type sql_value() :: number() | nil | iodata() | {'$blob', iodata()}.
%% SQL value type.

-type bind_value() :: sql_value() | {pos_integer() | atom(), sql_value()}.
%% List of values for statement parameters (see {@link bind/3}).

%% @doc Load NIF
init() ->
    NifName = "esqlcipher_nif",
    NifFileName = case code:priv_dir(esqlcipher) of
                      {error, bad_name} -> filename:join("priv", NifName);
                      Dir -> filename:join(Dir, NifName)
                  end,
    ok = erlang:load_nif(NifFileName, 0).

%% @doc Start a low level thread which can handle sqlite3 calls.
%% @see esqlcipher:open/2
%% @see esqlcipher:open_encrypted/3
-spec start() -> {ok, reference()}.
start() ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Open the specified sqlite3 database.
%% Sends an asynchronous open command over the connection and returns `ok'
%% immediately.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:open/2
%% @see esqlcipher:open_encrypted/3
-spec open(connection(), reference(), pid(), iodata()) -> ok.
open(_Db, _Ref, _Dest, _Filename) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Close the sqlite3 connection.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:close/2
-spec close(connection(), reference(), pid()) -> ok.
close(_Db, _Ref, _Dest) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Give the encryption key for a specified sqlite3 database.
%% Note that there will be no error if the key is wrong -- try accessing the
%% database and look for a NOTADB error to check for that!
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:open_encrypted/3
-spec key(connection(), reference(), pid(), iodata()) -> ok.
key(_Db, _Ref, _Dest, _Key) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Change the encryption key for a specified sqlite3 database.
%% Note that this will only work once the database is decrypted, i.e. key/4 has
%% been called. On unencrypted databases, it will silently fail/do nothing.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:rekey/3
-spec rekey(connection(), reference(), pid(), iodata()) -> ok.
rekey(_Db, _Ref, _Dest, _Key) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Execute a query without returning any resulting rows.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:exec/3
-spec exec(connection(), reference(), pid(), sql()) -> ok.
exec(_Db, _Ref, _Dest, _Sql) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Execute a query, returning the last inserted row's rowid.
%%
%% Returns a message of the format
%%
%% `{ok, integer()} | sqlite_error()'
%% @see esqlcipher:insert/3
-spec insert(connection(), reference(), pid(), sql()) -> ok.
insert(_Db, _Ref, _Dest, _Sql) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Create a prepared statement
%%
%% Returns a message of the format
%%
%% `{ok} | sqlite_error()'
%% @see esqlcipher:prepare/3
%%
-spec prepare(connection(), reference(), pid(), sql()) -> ok.
prepare(_Db, _Ref, _Dest, _Sql) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Bind parameters to a prepared statement.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:bind/3
-spec bind(connection(), statement(), reference(), pid(), [bind_value()]) -> ok.
bind(_Db, _Stmt, _Ref, _Dest, _Args) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Run sqlite3's `step' multiple times to get chunks of rows.
%% Called internally by {@link esqlcipher:fetch_one/2},
%% {@link esqlcipher:fetch_chunk/3}, {@link esqlcipher:fetch_all/3} and others.
%%
%% Returns a message of the format
%%
%% ``{rows | '$done' | '$busy', [row()]} | sqlite_error()''
%% where row() is a list of values
-spec multi_step(connection(), statement(), pos_integer(), reference(), pid()) -> ok.
multi_step(_Db, _Stmt, _Chunk_Size, _Ref, _Dest) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Resets a prepared statement to its initial state, optionally clearing bound values.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:reset/3
-spec reset(connection(), statement(), reference(), pid(), boolean()) -> ok.
reset(_Db, _Stmt, _Ref, _Dest, _ClearValues) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Get the number of rows affected by the last update, insert, or delete
%% statement.
%%
%% Returns a message of the format
%%
%% `{ok, integer()} | sqlite_error()'
%% @see esqlcipher:changes/2
-spec changes(connection(), reference(), pid()) -> ok.
changes(_Db, _Ref, _Dest) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Retrieve the column names of the prepared statement.
%%
%% Returns a message of the format
%%
%% `{ok, [binary()]} | sqlite_error()'
%% @see esqlcipher:column_names/2
-spec column_names(connection(), statement(), reference(), pid()) -> ok.
column_names(_Db, _Stmt, _Ref, _Dest) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Retrieve the column types of the prepared statement
%%
%% Returns a message of the format
%%
%% `{ok, [binary()]} | sqlite_error()'
%% @see esqlcipher:column_types/2
-spec column_types(connection(), statement(), reference(), pid()) -> ok.
column_types(_Db, _Stmt, _Ref, _Dest) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Returns whether or not the database is in autocommit mode.
%%
%% Returns a message of the format
%%
%% `boolean()'
%% @see esqlcipher:get_autocommit/2
-spec get_autocommit(connection(), reference(), pid()) -> ok.
get_autocommit(_Db, _Ref, _Dest) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Set an update hook that will be called for any database changes.
%%
%% Returns a message of the format
%%
%% `ok | sqlite_error()'
%% @see esqlcipher:set_update_hook/3
-spec set_update_hook(connection(), reference(), pid(), pid()) -> ok.
set_update_hook(_Db, _Ref, _Dest, _Pid) ->
    erlang:nif_error(nif_library_not_loaded).