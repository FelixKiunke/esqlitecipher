%%
%% Test suite for esqlcipher.
%%

-module(esqlcipher_test).

-include_lib("eunit/include/eunit.hrl").

open_memory() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    {Db, ":memory:", memory}.

close_memory({Db, _Filename, _}) ->
    ok = esqlcipher:close(Db).

open_file() ->
    Filename = tempfile:name("test_db_"),
    {ok, Db} = esqlcipher:open(Filename),
    {Db, Filename, plaintext}.

open_enc_file() ->
    Filename = tempfile:name("test_enc_db_"),
    {ok, Db} = esqlcipher:open_encrypted(Filename, "password"),
    {Db, Filename, encrypted}.

close_file({Db, Filename, _}) ->
    ok = esqlcipher:close(Db),
    ok = file:delete(Filename).

% All tests in test_suite() are run with all 3 database types
% (in-memory, unencrypted file, encrypted file)
esqlcipher_test_() ->
    Tests = test_suite(),
    [{"with :memory: database",
      {foreach, fun open_memory/0, fun close_memory/1, Tests}},
     {"with unencrypted temporary database",
      {foreach, fun open_file/0, fun close_file/1, Tests}},
     {"with encrypted temporary database",
      {foreach, fun open_enc_file/0, fun close_file/1, Tests}}].

encryption_test_() ->
    [{foreach,
     fun() -> tempfile:name("test_enc_db_") end,
     fun(Filename) -> file:delete(Filename) end,
     enc_test_suite()}].

enc_test_suite() -> [
    fun(Filename) ->
        {"encryption_test", ?_test(begin
            {ok, Db} = esqlcipher:open_encrypted(Filename, "password"),
            true = esqlcipher:is_encrypted(Db),
            ok = esqlcipher:exec("create table test(a int, b text);", Db),
            ok = esqlcipher:exec("insert into test values(1, 'foo');", Db),
            {error, {baddb, _}} = esqlcipher:open(Filename),
            ok = esqlcipher:close(Db),
            {error, {baddb, _}} = esqlcipher:open_encrypted(Filename, "1234"),
            {ok, Db2} = esqlcipher:open_encrypted(Filename, "password"),
            [[1]] = esqlcipher:q("select a from test", Db2),
            ok = esqlcipher:close(Db2),
            ok
        end)}
    end,

    fun(Filename) ->
        {"encryption_rekey_test", ?_test(begin
            {ok, Db} = esqlcipher:open_encrypted(Filename, "password"),
            true = esqlcipher:is_encrypted(Db),
            ok = esqlcipher:exec("create table test(a int, b text);", Db),
            ok = esqlcipher:exec("insert into test values(1, 'foo');", Db),
            {error, {baddb, _}} = esqlcipher:open(Filename),
            ok = esqlcipher:rekey("1234", Db),
            true = esqlcipher:is_encrypted(Db),
            ok = esqlcipher:close(Db),
            {error, {baddb, _}} = esqlcipher:open(Filename),
            {error, {baddb, _}} = esqlcipher:open_encrypted(Filename, "password"),
            {ok, Db2} = esqlcipher:open_encrypted(Filename, "1234"),
            [[1]] = esqlcipher:q("select a from test", Db2),
            ok = esqlcipher:close(Db2),
            ok
        end)}
    end,

    fun(Filename) ->
        {"encryption_invalid_rekey_test", ?_test(begin
            {ok, Db} = esqlcipher:open(Filename),
            false = esqlcipher:is_encrypted(Db),
            ok = esqlcipher:exec("create table test(a int, b text);", Db),
            ok = esqlcipher:exec("insert into test values(1, 'foo');", Db),
            {error, {rekey_plaintext, _}} = esqlcipher:rekey("1234", Db),
            ok = esqlcipher:close(Db),
            ok
        end)}
    end
].

test_suite() -> [
    fun({Db, Filename, Type}) -> {"open_reopen", ?_test(begin
            ok = esqlcipher:exec("CREATE TABLE test (val INTEGER);", Db),
            ok = esqlcipher:exec("INSERT INTO test (val) VALUES (1), (2), (3);", Db),
            3 = esqlcipher:changes(Db),
            esqlcipher:close(Db),
            {ok, Db2} = case Type of
                encrypted -> esqlcipher:open_encrypted(Filename, "password");
                _ -> esqlcipher:open(Filename)
            end,
            case Type of
                memory ->
                    {error, {sqlite_error, _}} = esqlcipher:exec("SELECT val FROM test LIMIT 2;", Db2);
                _ ->
                    [[1], [2]] = esqlcipher:q("SELECT val FROM test LIMIT 2;", Db2)
            end,
            ok = esqlcipher:close(Db2),
            file:write_file("/Users/Felix/git/esqlcipher/test.txt", "hallo"),
            ok
        end)}
    end,

    fun({Db, Filename, Type}) ->
        {"open_multiple_times", ?_test(begin
            {ok, Db2} = case Type of
                encrypted -> esqlcipher:open_encrypted(Filename, "password");
                _ -> esqlcipher:open(Filename)
            end,
            ok = esqlcipher:exec("CREATE TABLE test (val INTEGER);", Db),
            ok = esqlcipher:exec("INSERT INTO test (val) VALUES (1), (2), (3);", Db),
            3 = esqlcipher:changes(Db),
            0 = esqlcipher:changes(Db2),
            case Type of
                memory ->
                    {error, {sqlite_error, _}} = esqlcipher:exec("SELECT val FROM test LIMIT 2;", Db2);
                _ ->
                    [[1], [2]] = esqlcipher:q("SELECT val FROM test LIMIT 2;", Db2)
            end,
            ok = esqlcipher:close(Db2),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"open_multiple_different", ?_test(begin
            Fn2 = tempfile:name("test_db_"),
            {ok, Db2} = esqlcipher:open(Fn2),
            ok = esqlcipher:exec("CREATE TABLE test (val INTEGER);", Db),
            ok = esqlcipher:exec("INSERT INTO test (val) VALUES (1), (2), (3);", Db),
            3 = esqlcipher:changes(Db),
            ok = esqlcipher:exec("CREATE TABLE test (val INTEGER);", Db2),
            ok = esqlcipher:exec("INSERT INTO test (val) VALUES (4), (5);", Db2),
            2 = esqlcipher:changes(Db2),
            [[4], [5]] = esqlcipher:q("SELECT val FROM test LIMIT 2;", Db2),
            [[1], [2]] = esqlcipher:q("SELECT val FROM test LIMIT 2;", Db),
            ok = esqlcipher:close(Db2),
            file:delete(Fn2),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"get_autocommit", ?_test(begin
            ok = esqlcipher:exec("CREATE TABLE test (id INTEGER PRIMARY KEY, val STRING);", Db),
            true = esqlcipher:get_autocommit(Db),
            ok = esqlcipher:exec("BEGIN;", Db),
            false = esqlcipher:get_autocommit(Db),
            ok = esqlcipher:exec("INSERT INTO test (val) VALUES ('this is a test');", Db),
            ok = esqlcipher:exec("COMMIT;", Db),
            true = esqlcipher:get_autocommit(Db),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"update_hook", ?_test(begin
            ok = esqlcipher:set_update_hook(self(), Db),
            ok = esqlcipher:exec("CREATE TABLE test (id INTEGER PRIMARY KEY, val STRING);", Db),
            ok = esqlcipher:exec("INSERT INTO test (val) VALUES ('this is a test');", Db),
            ok = receive {insert, "test", 1} -> ok after 150 -> no_message end,
            ok = esqlcipher:exec("UPDATE test SET val = 'a new test' WHERE id = 1;", Db),
            ok = receive {update, "test", 1} -> ok after 150 -> no_message end,
            ok = esqlcipher:exec("DELETE FROM test WHERE id = 1;", Db),
            ok = receive {delete, "test", 1} -> ok after 150 -> no_message end,
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"simple_query", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello1'", ",", "10" ");"], Db),
            1 = esqlcipher:changes(Db),

            ok = esqlcipher:exec(["insert into test_table values(", "'hello2'", ",", "11" ");"], Db),
            1 = esqlcipher:changes(Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello3'", ",", "12" ");"], Db),
            1 = esqlcipher:changes(Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello4'", ",", "13" ");"], Db),
            1 = esqlcipher:changes(Db),
            ok = esqlcipher:exec("commit;", Db),
            ok = esqlcipher:exec("select * from test_table;", Db),

            ok = esqlcipher:exec("delete from test_table;", Db),
            4 = esqlcipher:changes(Db),
            
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"prepare", ?_test(begin
            esqlcipher:exec("begin;", Db),
            esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            {ok, Statement} = esqlcipher:prepare("insert into test_table values('one', 2)", Db),

            {ok, nil} = esqlcipher:fetch_one(Statement),
            1 = esqlcipher:changes(Db),

            ok = esqlcipher:exec(["insert into test_table values(", "'hello4'", ",", "13" ");"], Db),

            %% Check if the values are there.
            [[<<"one">>, 2], [<<"hello4">>, 13]] = esqlcipher:q("select * from test_table order by two", Db),
            esqlcipher:exec("commit;", Db),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        %% TODO: Test named binds; test reset with clearvalues
        {"bind", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec("commit;", Db),

            %% Create a prepared statement
            {ok, Statement} = esqlcipher:prepare("insert into test_table values(?1, ?2)", Db),
            {error, {badarg, _}} = esqlcipher:bind(Statement, [one, 2]),
            ok = esqlcipher:run(Statement),
            ok = esqlcipher:bind(Statement, ["three", 4]),
            ok = esqlcipher:run(Statement),
            ok = esqlcipher:bind(Statement, ["five", 6]),
            ok = esqlcipher:run(Statement),
            ok = esqlcipher:bind(Statement, [[<<"se">>, $v, "en"], 8]), % iolist bound as text
            ok = esqlcipher:run(Statement),
            ok = esqlcipher:bind(Statement, [<<"nine">>, 10]), % iolist bound as text
            ok = esqlcipher:run(Statement),
            ok = esqlcipher:bind(Statement, [{'$blob', [<<"eleven">>, 0]}, 12]), % iolist bound as blob with trailing eos.
            ok = esqlcipher:run(Statement),

            %% int64
            ok = esqlcipher:bind(Statement, ["int64", 308553449069486081]),
            ok = esqlcipher:run(Statement),

            %% negative int64
            ok = esqlcipher:bind(Statement, ["negative_int64", -308553449069486081]),
            ok = esqlcipher:run(Statement),


            %% utf-8
            ok = esqlcipher:bind(Statement, [[<<228,184,138,230,181,183>>], 100]),
            ok = esqlcipher:run(Statement),

            ?assertEqual([],
                esqlcipher:q("select one, two from test_table where two = '2'", Db)),
            ?assertEqual([[<<"three">>, 4]],
                esqlcipher:q("select one, two from test_table where two = 4", Db)),
            ?assertEqual([[<<"five">>, 6]],
                esqlcipher:q("select one, two from test_table where two = 6", Db)),
            ?assertEqual([[<<"seven">>, 8]],
                esqlcipher:q("select one, two from test_table where two = 8", Db)),
            ?assertEqual([[<<"nine">>, 10]],
                esqlcipher:q("select one, two from test_table where two = 10", Db)),
            ?assertEqual([[{'$blob', <<$e,$l,$e,$v,$e,$n,0>>}, 12]],
                esqlcipher:q("select one, two from test_table where two = 12", Db)),

            ?assertEqual([[<<"int64">>, 308553449069486081]],
                esqlcipher:q("select one, two from test_table where one = 'int64';", Db)),
            ?assertEqual([[<<"negative_int64">>, -308553449069486081]],
                esqlcipher:q("select one, two from test_table where one = 'negative_int64';", Db)),

            %% utf-8
            ?assertEqual([[<<228,184,138,230,181,183>>, 100]],
                esqlcipher:q("select one, two from test_table where two = 100", Db)),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"bind_for_queries", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec("commit;", Db),

            ?assertThrow({error, {badarg, _}}, esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                        [test_table], Db)),
            ?assertEqual([[1]], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                        ["test_table"], Db)),
            ?assertEqual([[1]], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                        [<<"test_table">>], Db)),
            ?assertEqual([[1]], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                        [[<<"test_table">>]], Db)),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"column_names", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello1'", ",", "10" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello2'", ",", "20" ");"], Db),
            ok = esqlcipher:exec("commit;", Db),

            %% All columns
            {ok, Stmt} = esqlcipher:prepare("select * from test_table", Db),
            [<<"one">>, <<"two">>] =  esqlcipher:column_names(Stmt),
            {ok, [<<"hello1">>, 10]} = esqlcipher:fetch_one(Stmt),
            [<<"one">>, <<"two">>] =  esqlcipher:column_names(Stmt),
            {ok, [<<"hello2">>, 20]} = esqlcipher:fetch_one(Stmt),
            [<<"one">>, <<"two">>] =  esqlcipher:column_names(Stmt),
            ok = esqlcipher:run(Stmt),
            [<<"one">>, <<"two">>] =  esqlcipher:column_names(Stmt),

            %% One column
            {ok, Stmt2} = esqlcipher:prepare("select two from test_table", Db),
            [<<"two">>] =  esqlcipher:column_names(Stmt2),
            {ok, [10]} = esqlcipher:fetch_one(Stmt2),
            [<<"two">>] =  esqlcipher:column_names(Stmt2),
            {ok, [20]} = esqlcipher:fetch_one(Stmt2),
            [<<"two">>] =  esqlcipher:column_names(Stmt2),
            {ok, nil} = esqlcipher:fetch_one(Stmt2),
            [<<"two">>] =  esqlcipher:column_names(Stmt2),

            %% No columns
            {ok, Stmt3} = esqlcipher:prepare("values(1);", Db),
            [<<"column1">>] =  esqlcipher:column_names(Stmt3),
            {ok, [1]} = esqlcipher:fetch_one(Stmt3),
            [<<"column1">>] =  esqlcipher:column_names(Stmt3),

            %% Things get a bit weird when you retrieve the column name
            %% when calling an aggragage function.
            {ok, Stmt4} = esqlcipher:prepare("select date('now');", Db),
            [<<"date('now')">>] =  esqlcipher:column_names(Stmt4),
            {ok, [Date]} = esqlcipher:fetch_one(Stmt4),
            true = is_binary(Date),

            %% Some statements have no column names
            {ok, Stmt5} = esqlcipher:prepare("create table dummy(a, b, c);", Db),
            [] = esqlcipher:column_names(Stmt5),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"column_types", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello1'", ",", "10" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello2'", ",", "20" ");"], Db),
            ok = esqlcipher:exec("commit;", Db),

            %% All columns
            {ok, Stmt} = esqlcipher:prepare("select * from test_table", Db),
            [<<"varchar(10)">>, <<"int">>] = esqlcipher:column_types(Stmt),
            {ok, [<<"hello1">>, 10]} = esqlcipher:fetch_one(Stmt),
            [<<"varchar(10)">>, <<"int">>] = esqlcipher:column_types(Stmt),
            {ok, [<<"hello2">>, 20]} = esqlcipher:fetch_one(Stmt),
            [<<"varchar(10)">>, <<"int">>] = esqlcipher:column_types(Stmt),
            ok = esqlcipher:run(Stmt),
            [<<"varchar(10)">>, <<"int">>] = esqlcipher:column_types(Stmt),

            %% Some statements have no column types
            {ok, Stmt2} = esqlcipher:prepare("create table dummy(a, b, c);", Db),
            [] = esqlcipher:column_types(Stmt2),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"nil_column_types", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table t1(c1 variant);", Db),
            ok = esqlcipher:exec("commit;", Db),

            {ok, Stmt} = esqlcipher:prepare("select c1 + 1, c1 from t1", Db),
            [nil, <<"variant">>] = esqlcipher:column_types(Stmt),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"reset", ?_test(begin
            {ok, Stmt} = esqlcipher:prepare("select * from (values (1), (2));", Db),
            {ok, [1]} = esqlcipher:fetch_one(Stmt),

            ok = esqlcipher:reset(Stmt),
            {ok, [1]} = esqlcipher:fetch_one(Stmt),
            {ok, [2]} = esqlcipher:fetch_one(Stmt),
            ok = esqlcipher:run(Stmt),

            % After a done the statement is automatically reset.
            {ok, [1]} = esqlcipher:fetch_one(Stmt),

            % Calling reset multiple times...
            ok = esqlcipher:reset(Stmt),
            ok = esqlcipher:reset(Stmt),
            ok = esqlcipher:reset(Stmt),
            ok = esqlcipher:reset(Stmt),

            % The statement should still be reset.
            {ok, [1]} = esqlcipher:fetch_one(Stmt),

            ok
        end)}
    end,


    fun({Db, _Filename, _Type}) ->
        {"foreach", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello1'", ",", "10" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello2'", ",", "11" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello3'", ",", "12" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello4'", ",", "13" ");"], Db),
            ok = esqlcipher:exec("commit;", Db),

            F = fun(Row) ->
                case Row of
                    [Key, Value] ->
                    	put(Key, Value);
                    _ ->
                    	ok
                end
            end,

            esqlcipher:foreach(F, "select * from test_table;", Db),

            10 = get(<<"hello1">>),
            11 = get(<<"hello2">>),
            12 = get(<<"hello3">>),
            13 = get(<<"hello4">>),

            Assoc = fun([<<"one">>, <<"two">>] = Names, [Key, _] = Row) ->
                put({assoc, Key}, lists:zip(Names, Row))
            end,

            esqlcipher:foreach(Assoc, "select * from test_table;", Db),

            [{<<"one">>,<<"hello1">>},{<<"two">>,10}] = get({assoc, <<"hello1">>}),
            [{<<"one">>,<<"hello2">>},{<<"two">>,11}] = get({assoc, <<"hello2">>}),
            [{<<"one">>,<<"hello3">>},{<<"two">>,12}] = get({assoc, <<"hello3">>}),
            [{<<"one">>,<<"hello4">>},{<<"two">>,13}] = get({assoc, <<"hello4">>}),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"map", ?_test(begin
            ok = esqlcipher:exec("begin;", Db),
            ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello1'", ",", "10" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello2'", ",", "11" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello3'", ",", "12" ");"], Db),
            ok = esqlcipher:exec(["insert into test_table values(", "'hello4'", ",", "13" ");"], Db),
            ok = esqlcipher:exec("commit;", Db),

            F = fun(Row) -> Row end,
            
            [[<<"hello1">>,10],[<<"hello2">>,11],[<<"hello3">>,12],[<<"hello4">>,13]]
                = esqlcipher:map(F, "select * from test_table", Db),

            %% Test that when the row-names are added..
            Assoc = fun(Names, Row) ->
                lists:zip(Names, Row)
            end,

            [[{<<"one">>,<<"hello1">>},{<<"two">>,10}],
             [{<<"one">>,<<"hello2">>},{<<"two">>,11}],
             [{<<"one">>,<<"hello3">>},{<<"two">>,12}],
             [{<<"one">>,<<"hello4">>},{<<"two">>,13}]] = esqlcipher:map(Assoc, "select * from test_table", Db),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"error1_msg", ?_test(begin
            %% Not sql.
            {error, {sqlite_error, _Msg1}} = esqlcipher:exec("dit is geen sql", Db),

            %% Database test does not exist.
            {error, {sqlite_error, _Msg2}} = esqlcipher:exec("select * from test;", Db),

            %% Opening non-existant database.
            {error, {cantopen, _Msg3}} = esqlcipher:open("/dit/bestaat/niet"),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"prepare_and_close_connection", ?_test(begin
            [] = esqlcipher:q("create table test(one, two, three)", Db),
            ok = esqlcipher:exec(["insert into test values(1,2,3);"], Db),
            {ok, Stmt} = esqlcipher:prepare("select * from test", Db),

            %% The prepated statment works.
            {ok, [1,2,3]} = esqlcipher:fetch_one(Stmt),
            ok = esqlcipher:run(Stmt),

            ok = esqlcipher:close(Db),

            ok = esqlcipher:reset(Stmt),

            %% Internally sqlite3_close_v2 is used by the nif. This will destruct the
            %% connection when the last perpared statement is finalized
            {ok, [1,2,3]} = esqlcipher:fetch_one(Stmt),
            ok = esqlcipher:run(Stmt),

            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"sqlite_version", ?_test(begin
            {ok, Stmt} = esqlcipher:prepare("select sqlite_version() as sqlite_version;", Db),
            [<<"sqlite_version">>] =  esqlcipher:column_names(Stmt),
            ?assertEqual({ok, [<<"3.36.0">>]}, esqlcipher:fetch_one(Stmt)),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"sqlcipher_version", ?_test(begin
            {ok, Stmt} = esqlcipher:prepare("PRAGMA cipher_version;", Db),
            [<<"cipher_version">>] =  esqlcipher:column_names(Stmt),
            ?assertEqual({ok, [<<"4.5.0 community">>]}, esqlcipher:fetch_one(Stmt)),
            ok
        end)}
    end,

    fun({Db, _Filename, _Type}) ->
        {"sqlite_source_id", ?_test(begin
            {ok, Stmt} = esqlcipher:prepare("select sqlite_source_id() as sqlite_source_id;", Db),
            [<<"sqlite_source_id">>] =  esqlcipher:column_names(Stmt),
            ?assertEqual({ok, [<<"2021-06-18 18:36:39 5c9a6c06871cb9fe42814af9c039eb6da5427a6ec28f187af7ebfb62eafaalt1">>]}, esqlcipher:fetch_one(Stmt)),
            ok
        end)}
    end
].

garbage_collect_test() ->
    F = fun() ->
        {ok, Db} = esqlcipher:open(":memory:"),
        [] = esqlcipher:q("create table test(one, two, three)", Db),
        {ok, Stmt} = esqlcipher:prepare("select * from test", Db),
        {ok, nil} = esqlcipher:fetch_one(Stmt)
    end,

    [spawn(F) || _X <- lists:seq(0,30)],
    receive after 500 -> ok end,
    erlang:garbage_collect(),

    [spawn(F) || _X <- lists:seq(0,30)],
    receive after 500 -> ok end,
    erlang:garbage_collect(),

    ok.