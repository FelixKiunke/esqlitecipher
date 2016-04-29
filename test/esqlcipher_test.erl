%%
%% Test suite for esqlcipher.
%%

-module(esqlcipher_test).

-include_lib("eunit/include/eunit.hrl").

open_single_database_test() ->
    {ok, _C1} = esqlcipher:open("test.db"),
    ok.

open_multiple_same_databases_test() ->
    {ok, _C1} = esqlcipher:open("test.db"),
    {ok, _C2} = esqlcipher:open("test.db"),
    ok.

open_multiple_different_databases_test() ->
    {ok, _C1} = esqlcipher:open("test1.db"),
    {ok, _C2} = esqlcipher:open("test2.db"),
    ok.

encryption_test() ->
    {ok, Db} = esqlcipher:open_encrypted("test_enc.db", "password"),
    ok = esqlcipher:exec("create table test(a int, b text);", Db),
    ok = esqlcipher:rekey("1234", Db),
    ok = esqlcipher:close(Db),
    {ok, _} = esqlcipher:open_encrypted("test_enc.db", "1234"),
    file:delete("test_enc.db"),
    ok.

get_autocommit_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("CREATE TABLE test (id INTEGER PRIMARY KEY, val STRING);", Db),
    true = esqlcipher:get_autocommit(Db),
    ok = esqlcipher:exec("BEGIN;", Db),
    false = esqlcipher:get_autocommit(Db),
    ok = esqlcipher:exec("INSERT INTO test (val) VALUES ('this is a test');", Db),
    ok = esqlcipher:exec("COMMIT;", Db),
    true = esqlcipher:get_autocommit(Db),
    ok.

update_hook_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:set_update_hook(self(), Db),
    ok = esqlcipher:exec("CREATE TABLE test (id INTEGER PRIMARY KEY, val STRING);", Db),
    ok = esqlcipher:exec("INSERT INTO test (val) VALUES ('this is a test');", Db),
    ok = receive {insert, "test", 1} -> ok after 150 -> no_message end,
    ok = esqlcipher:exec("UPDATE test SET val = 'a new test' WHERE id = 1;", Db),
    ok = receive {update, "test", 1} -> ok after 150 -> no_message end,
    ok = esqlcipher:exec("DELETE FROM test WHERE id = 1;", Db),
    ok = receive {delete, "test", 1} -> ok after 150 -> no_message end,
    ok.

simple_query_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello1\"", ",", "10" ");"], Db),
    {ok, 1} = esqlcipher:changes(Db),

    ok = esqlcipher:exec(["insert into test_table values(", "\"hello2\"", ",", "11" ");"], Db),
    {ok, 1} = esqlcipher:changes(Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello3\"", ",", "12" ");"], Db),
    {ok, 1} = esqlcipher:changes(Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello4\"", ",", "13" ");"], Db),
    {ok, 1} = esqlcipher:changes(Db),
    ok = esqlcipher:exec("commit;", Db),
    ok = esqlcipher:exec("select * from test_table;", Db),

    ok = esqlcipher:exec("delete from test_table;", Db),
    {ok, 4} = esqlcipher:changes(Db),
    
    ok.

prepare_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    esqlcipher:exec("begin;", Db),
    esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    {ok, Statement} = esqlcipher:prepare("insert into test_table values(\"one\", 2)", Db),
    
    '$done' = esqlcipher:step(Statement),
    {ok, 1} = esqlcipher:changes(Db),

    ok = esqlcipher:exec(["insert into test_table values(", "\"hello4\"", ",", "13" ");"], Db),

    %% Check if the values are there.
    [{<<"one">>, 2}, {<<"hello4">>, 13}] = esqlcipher:q("select * from test_table order by two", Db),
    esqlcipher:exec("commit;", Db),
    esqlcipher:close(Db),

    ok.

bind_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec("commit;", Db),

    %% Create a prepared statement
    {ok, Statement} = esqlcipher:prepare("insert into test_table values(?1, ?2)", Db),
    esqlcipher:bind(Statement, [one, 2]),
    esqlcipher:step(Statement),
    esqlcipher:bind(Statement, ["three", 4]),
    esqlcipher:step(Statement),
    esqlcipher:bind(Statement, ["five", 6]),
    esqlcipher:step(Statement),
    esqlcipher:bind(Statement, [[<<"se">>, $v, "en"], 8]), % iolist bound as text
    esqlcipher:step(Statement),
    esqlcipher:bind(Statement, [<<"nine">>, 10]), % iolist bound as text
    esqlcipher:step(Statement),
    esqlcipher:bind(Statement, [{blob, [<<"eleven">>, 0]}, 12]), % iolist bound as blob with trailing eos.
    esqlcipher:step(Statement),

    %% int64
    esqlcipher:bind(Statement, [int64, 308553449069486081]),
    esqlcipher:step(Statement),

    %% negative int64
    esqlcipher:bind(Statement, [negative_int64, -308553449069486081]),
    esqlcipher:step(Statement),


    %% utf-8
    esqlcipher:bind(Statement, [[<<228,184,138,230,181,183>>], 100]),
    esqlcipher:step(Statement),

    ?assertEqual([{<<"one">>, 2}],
        esqlcipher:q("select one, two from test_table where two = '2'", Db)),
    ?assertEqual([{<<"three">>, 4}],
        esqlcipher:q("select one, two from test_table where two = 4", Db)),
    ?assertEqual([{<<"five">>, 6}],
        esqlcipher:q("select one, two from test_table where two = 6", Db)),
    ?assertEqual([{<<"seven">>, 8}],
        esqlcipher:q("select one, two from test_table where two = 8", Db)),
    ?assertEqual([{<<"nine">>, 10}],
        esqlcipher:q("select one, two from test_table where two = 10", Db)),
    ?assertEqual([{{blob, <<$e,$l,$e,$v,$e,$n,0>>}, 12}],
        esqlcipher:q("select one, two from test_table where two = 12", Db)),

    ?assertEqual([{<<"int64">>, 308553449069486081}],
        esqlcipher:q("select one, two from test_table where one = 'int64';", Db)),
    ?assertEqual([{<<"negative_int64">>, -308553449069486081}],
        esqlcipher:q("select one, two from test_table where one = 'negative_int64';", Db)),

    %% utf-8
    ?assertEqual([{<<228,184,138,230,181,183>>, 100}],
        esqlcipher:q("select one, two from test_table where two = 100", Db)),

    ok.

bind_for_queries_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec("commit;", Db),

    ?assertEqual([{1}], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                [test_table], Db)),
    ?assertEqual([{1}], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                ["test_table"], Db)),
    ?assertEqual([{1}], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                [<<"test_table">>], Db)),
    ?assertEqual([{1}], esqlcipher:q(<<"SELECT count(type) FROM sqlite_master WHERE type='table' AND name=?;">>,
                [[<<"test_table">>]], Db)),

    ok.

column_names_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello1\"", ",", "10" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello2\"", ",", "20" ");"], Db),
    ok = esqlcipher:exec("commit;", Db),

    %% All columns
    {ok, Stmt} = esqlcipher:prepare("select * from test_table", Db),
    {one, two} =  esqlcipher:column_names(Stmt),
    {row, {<<"hello1">>, 10}} = esqlcipher:step(Stmt),
    {one, two} =  esqlcipher:column_names(Stmt),
    {row, {<<"hello2">>, 20}} = esqlcipher:step(Stmt),
    {one, two} =  esqlcipher:column_names(Stmt),
    '$done' = esqlcipher:step(Stmt),
    {one, two} =  esqlcipher:column_names(Stmt),

    %% One column
    {ok, Stmt2} = esqlcipher:prepare("select two from test_table", Db),
    {two} =  esqlcipher:column_names(Stmt2),
    {row, {10}} = esqlcipher:step(Stmt2),
    {two} =  esqlcipher:column_names(Stmt2),
    {row, {20}} = esqlcipher:step(Stmt2),
    {two} =  esqlcipher:column_names(Stmt2),
    '$done' = esqlcipher:step(Stmt2),
    {two} =  esqlcipher:column_names(Stmt2),

    %% No columns
    {ok, Stmt3} = esqlcipher:prepare("values(1);", Db),
    {column1} =  esqlcipher:column_names(Stmt3),
    {row, {1}} = esqlcipher:step(Stmt3),
    {column1} =  esqlcipher:column_names(Stmt3),

    %% Things get a bit weird when you retrieve the column name
    %% when calling an aggragage function.
    {ok, Stmt4} = esqlcipher:prepare("select date('now');", Db),
    {'date(\'now\')'} =  esqlcipher:column_names(Stmt4),
    {row, {Date}} = esqlcipher:step(Stmt4),
    true = is_binary(Date),

    %% Some statements have no column names
    {ok, Stmt5} = esqlcipher:prepare("create table dummy(a, b, c);", Db),
    {} = esqlcipher:column_names(Stmt5),

    ok.

column_types_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello1\"", ",", "10" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello2\"", ",", "20" ");"], Db),
    ok = esqlcipher:exec("commit;", Db),

    %% All columns
    {ok, Stmt} = esqlcipher:prepare("select * from test_table", Db),
    {'varchar(10)', int} =  esqlcipher:column_types(Stmt),
    {row, {<<"hello1">>, 10}} = esqlcipher:step(Stmt),
    {'varchar(10)', int} =  esqlcipher:column_types(Stmt),
    {row, {<<"hello2">>, 20}} = esqlcipher:step(Stmt),
    {'varchar(10)', int} =  esqlcipher:column_types(Stmt),
    '$done' = esqlcipher:step(Stmt),
    {'varchar(10)', int} =  esqlcipher:column_types(Stmt),

    %% Some statements have no column types
    {ok, Stmt2} = esqlcipher:prepare("create table dummy(a, b, c);", Db),
    {} = esqlcipher:column_types(Stmt2),

    ok.

nil_column_types_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table t1(c1 variant);", Db),
    ok = esqlcipher:exec("commit;", Db),

    {ok, Stmt} = esqlcipher:prepare("select c1 + 1, c1 from t1", Db),
    {nil, variant} =  esqlcipher:column_types(Stmt),
    ok.

reset_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),

    {ok, Stmt} = esqlcipher:prepare("select * from (values (1), (2));", Db),
    {row, {1}} = esqlcipher:step(Stmt),

    ok = esqlcipher:reset(Stmt),
    {row, {1}} = esqlcipher:step(Stmt),
    {row, {2}} = esqlcipher:step(Stmt),
    '$done' = esqlcipher:step(Stmt),

    % After a done the statement is automatically reset.
    {row, {1}} = esqlcipher:step(Stmt),

    % Calling reset multiple times...
    ok = esqlcipher:reset(Stmt),
    ok = esqlcipher:reset(Stmt),
    ok = esqlcipher:reset(Stmt),
    ok = esqlcipher:reset(Stmt),

    % The statement should still be reset.
    {row, {1}} = esqlcipher:step(Stmt),

    ok.


foreach_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello1\"", ",", "10" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello2\"", ",", "11" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello3\"", ",", "12" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello4\"", ",", "13" ");"], Db),
    ok = esqlcipher:exec("commit;", Db),

    F = fun(Row) ->
		case Row of
		    {Key, Value} ->
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

    ok.

map_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    ok = esqlcipher:exec("begin;", Db),
    ok = esqlcipher:exec("create table test_table(one varchar(10), two int);", Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello1\"", ",", "10" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello2\"", ",", "11" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello3\"", ",", "12" ");"], Db),
    ok = esqlcipher:exec(["insert into test_table values(", "\"hello4\"", ",", "13" ");"], Db),
    ok = esqlcipher:exec("commit;", Db),

    F = fun(Row) -> Row end,
    
    [{<<"hello1">>,10},{<<"hello2">>,11},{<<"hello3">>,12},{<<"hello4">>,13}]
        = esqlcipher:map(F, "select * from test_table", Db),

    %% Test that when the row-names are added..
    Assoc = fun(Names, Row) ->
		    lists:zip(tuple_to_list(Names), tuple_to_list(Row))
	    end,

    [[{one,<<"hello1">>},{two,10}],
     [{one,<<"hello2">>},{two,11}],
     [{one,<<"hello3">>},{two,12}],
     [{one,<<"hello4">>},{two,13}]]  = esqlcipher:map(Assoc, "select * from test_table", Db),

    ok.

error1_msg_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),

    %% Not sql.
    {error, {sqlite_error, _Msg1}} = esqlcipher:exec("dit is geen sql", Db),

    %% Database test does not exist.
    {error, {sqlite_error, _Msg2}} = esqlcipher:exec("select * from test;", Db),

    %% Opening non-existant database.
    {error, {cantopen, _Msg3}} = esqlcipher:open("/dit/bestaat/niet"),
    ok.

prepare_and_close_connection_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),

    [] = esqlcipher:q("create table test(one, two, three)", Db),
    ok = esqlcipher:exec(["insert into test values(1,2,3);"], Db),
    {ok, Stmt} = esqlcipher:prepare("select * from test", Db),

    %% The prepated statment works.
    {row, {1,2,3}} = esqlcipher:step(Stmt),
    '$done' = esqlcipher:step(Stmt),

    ok = esqlcipher:close(Db),

    ok = esqlcipher:reset(Stmt),

    %% Internally sqlite3_close_v2 is used by the nif. This will destruct the
    %% connection when the last perpared statement is finalized
    {row, {1,2,3}} = esqlcipher:step(Stmt),
    '$done' = esqlcipher:step(Stmt),

    ok.

sqlite_version_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    {ok, Stmt} = esqlcipher:prepare("select sqlite_version() as sqlite_version;", Db),
    {sqlite_version} =  esqlcipher:column_names(Stmt),
    ?assertEqual({row, {<<"3.33.0">>}}, esqlcipher:step(Stmt)),
    ok.

sqlcipher_version_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    {ok, Stmt} = esqlcipher:prepare("PRAGMA cipher_version;", Db),
    {cipher_version} =  esqlcipher:column_names(Stmt),
    ?assertEqual({row, {<<"4.4.2 community">>}}, esqlcipher:step(Stmt)),
    ok.

sqlite_source_id_test() ->
    {ok, Db} = esqlcipher:open(":memory:"),
    {ok, Stmt} = esqlcipher:prepare("select sqlite_source_id() as sqlite_source_id;", Db),
    {sqlite_source_id} =  esqlcipher:column_names(Stmt),
    ?assertEqual({row, {<<"2020-08-14 13:23:32 fca8dc8b578f215a969cd899336378966156154710873e68b3d9ac5881b0alt1">>}}, esqlcipher:step(Stmt)),
    ok.

garbage_collect_test() ->
    F = fun() ->
        {ok, Db} = esqlcipher:open(":memory:"),
        [] = esqlcipher:q("create table test(one, two, three)", Db),
        {ok, Stmt} = esqlcipher:prepare("select * from test", Db),
        '$done' = esqlcipher:step(Stmt)
    end,

    [spawn(F) || _X <- lists:seq(0,30)],
    receive after 500 -> ok end,
    erlang:garbage_collect(),

    [spawn(F) || _X <- lists:seq(0,30)],
    receive after 500 -> ok end,
    erlang:garbage_collect(),

    ok.
