:- begin_tests(verify).
:- use_module(verify).

% Test initMap/3
test(initMap_empty) :-
    initMap([], 0, Map),
    assertion(Map == []).

test(initMap_single) :-
    initMap([a], 1, Map),
    assertion(Map == [(a, 1)]).

test(initMap_multiple) :-
    initMap([a, b, c], 2, Map),
    assertion(Map == [(a, 2), (b, 2), (c, 2)]).

% Test mapUpsert/4
test(mapUpsert_update) :-
    mapUpsert(a, 1, [(a, 0), (b, 0)], NewMap),
    assertion(NewMap == [(a, 1), (b, 0)]).

test(mapUpsert_insert) :-
    mapUpsert(c, 2, [(a, 1), (b, 0)], NewMap),
    assertion(NewMap == [(c, 2), (a, 1), (b, 0)]).

test(mapUpsert_empty) :-
    mapUpsert(a, 1, [], NewMap),
    assertion(NewMap == [(a, 1)]).

% Test mapGet/3
test(mapGet_found) :-
    mapGet(a, [(a, 1), (b, 0)], Value),
    assertion(Value == 1).

test(mapGet_not_found) :-
    \+ mapGet(c, [(a, 1), (b, 0)], _).

test(mapGet_empty) :-
    \+ mapGet(a, [], _).

% Test initList/3
test(initList_zero) :-
    initList(0, 0, List),
    assertion(List == []).

test(initList_positive) :-
    initList(3, 7, List),
    assertion(List == [7, 7, 7]).

test(initList_single) :-
    initList(1, 5, List),
    assertion(List == [5]).

% Test listInsertAt/4
test(listInsertAt_start) :-
    listInsertAt(x, 0, [a, b, c], NewList),
    assertion(NewList == [x, b, c]).

test(listInsertAt_middle) :-
    listInsertAt(x, 2, [a, b, c, d], NewList),
    assertion(NewList == [a, b, x, d]).

test(listInsertAt_end) :-
    listInsertAt(x, 3, [a, b, c, d], NewList),
    assertion(NewList == [a, b, c, x]).

% Test initState/3
test(initState_no_identifiers_zero_threads) :-
    initState(program([], [], []), 0, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == []),
    assertion(ArrMap == []),
    assertion(IPs == []).

test(initState_multiple_vars_arrays) :-
    initState(program([a, b], [arr1, arr2], []), 3, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(a, 0), (b, 0)]),
    assertion(ArrMap == [(arr1, [0, 0, 0]), (arr2, [0, 0, 0])]),
    assertion(IPs == [1, 1, 1]).

test(initState_single_var_array) :-
    initState(program([x], [y], []), 2, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(x, 0)]),
    assertion(ArrMap == [(y, [0, 0])]),
    assertion(IPs == [1, 1]).

test(initState_empty_program) :-
    initState(program([], [], []), 5, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == []),
    assertion(ArrMap == []),
    assertion(IPs == [1, 1, 1, 1, 1]).

test(initState_multiple_vars_no_arrays) :-
    initState(program([v1, v2, v3], [], []), 4, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(v1, 0), (v2, 0), (v3, 0)]),
    assertion(ArrMap == []),
    assertion(IPs == [1, 1, 1, 1]).

test(initState_no_vars_multiple_arrays) :-
    initState(program([], [arr1, arr2], []), 3, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == []),
    assertion(ArrMap == [(arr1, [0, 0, 0]), (arr2, [0, 0, 0])]),
    assertion(IPs == [1, 1, 1]).

test(initState_single_var_large_array) :-
    initState(program([v1], [arr1], []), 10, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(v1, 0)]),
    assertion(ArrMap == [(arr1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]),
    assertion(IPs == [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]).

test(initState_non_integer_initialization) :-
    initState(program([a, b], [arr1], []), 2, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(a, 0), (b, 0)]),
    assertion(ArrMap == [(arr1, [0, 0])]),
    assertion(IPs == [1, 1]).

test(initState_large_threads) :-
    initState(program([x, y], [arr1], []), 10, state(VarMap, ArrMap, IPs)),
    length(IPs, Length),
    assertion(VarMap == [(x, 0), (y, 0)]),
    assertion(ArrMap == [(arr1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]),
    assertion(Length == 10).

test(initState_mixed_identifiers) :-
    initState(program([a, b], [arr1, arr2, arr3], []), 3, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(a, 0), (b, 0)]),
    assertion(ArrMap == [(arr1, [0, 0, 0]), (arr2, [0, 0, 0]), (arr3, [0, 0, 0])]),
    assertion(IPs == [1, 1, 1]).

test(initState_zero_threads) :-
    initState(program([a, b], [arr1, arr2], []), 0, state(VarMap, ArrMap, IPs)),
    assertion(VarMap == [(a, 0), (b, 0)]),
    assertion(ArrMap == [(arr1, []), (arr2, [])]),
    assertion(IPs == []).

% State used in tests
state(VarMap, ArrMap, IPs) :-
    VarMap = [(a, 10), (b, 20), (c, 30), (d, 1)],
    ArrMap = [(arr, [0, 1, 2, 3, 4]), (arr2, [10, 20, 30])],
    IPs = [1, 2, 3].

% Test evalExpr/4
test(evalExpr_pid) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(pid, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 2).

test(evalExpr_integer) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(42, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 42).

test(evalExpr_variable) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(a, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 10).

test(evalExpr_nonexistent_variable) :-
    state(VarMap, ArrMap, IPs),
    \+ evalExpr(nonexistent, state(VarMap, ArrMap, IPs), 2, _).

test(evalExpr_array_access) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(array(arr, 3), state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 3).

test(evalExpr_nested_array_access) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(array(arr2, array(arr, 1)), state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 20).

test(evalExpr_out_of_bounds) :-
    state(VarMap, ArrMap, IPs),
    \+ evalExpr(array(arr, 10), state(VarMap, ArrMap, IPs), 2, _).

test(evalExpr_array_index_variable) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(array(arr, d), state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 1).

test(evalExpr_complex_nested) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(array(arr2, array(arr, d)), state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 20).

test(evalExpr_arithmetic_add) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(a + b, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 30).

test(evalExpr_arithmetic_sub) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(c - a, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 20).

test(evalExpr_arithmetic_mul) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(b * 2, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 40).

test(evalExpr_arithmetic_div) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(c / a, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 3).

test(evalExpr_nested_arithmetic) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(((a + b) * c) / a, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 90).

test(evalExpr_invalid_array_index) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(array(arr, 1 + 2), state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 3).

test(evalExpr_pid_arithmetic_add) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(pid + 2, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 4).

test(evalExpr_pid_arithmetic_mul) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(pid * 3, state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 6).

test(evalExpr_pid_nested) :-
    state(VarMap, ArrMap, IPs),
    evalExpr(array(arr, pid), state(VarMap, ArrMap, IPs), 2, Value),
    assertion(Value == 2).

% New state used in tests
test_state(VarMap, ArrMap, IPs) :-
    VarMap = [(a, 10), (b, 20), (c, 30)],
    ArrMap = [(arr, [0, 1, 2, 3, 4]), (arr2, [10, 20, 30])],
    IPs = [1, 2, 3].

% Test evalStmt/4
test(evalStmt_assign_variable) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(assign(a, 42), state(VarMap, ArrMap, IPs), 1, state(NewVarMap, ArrMap, NewIPs)),
    assertion(NewVarMap == [(a, 42), (b, 20), (c, 30)]),
    assertion(NewIPs == [1, 3, 3]).

test(evalStmt_assign_array) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(assign(array(arr, 2), 42), state(VarMap, ArrMap, IPs), 1, state(VarMap, NewArrMap, NewIPs)),
    assertion(NewArrMap == [(arr, [0, 1, 42, 3, 4]), (arr2, [10, 20, 30])]),
    assertion(NewIPs == [1, 3, 3]).

test(evalStmt_sekcja) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(sekcja, state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 3, 3]).

test(evalStmt_goto) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(goto(5), state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 5, 3]).

test(evalStmt_condGoto_true) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(condGoto(b > a, 5), state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 5, 3]).

test(evalStmt_condGoto_false) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(condGoto(b < a, 5), state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 3, 3]).

test(incrementIP) :-
    test_state(_, _, IPs),
    incrementIP(1, IPs, NewIPs),
    assertion(NewIPs == [1, 3, 3]).

test(evalStmt_assign_nested_array) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(assign(array(arr2, array(arr, 1)), 42), state(VarMap, ArrMap, IPs), 1, state(VarMap, NewArrMap, NewIPs)),
    assertion(NewArrMap == [(arr2, [10, 42, 30]), (arr, [0, 1, 2, 3, 4])]),
    assertion(NewIPs == [1, 3, 3]).

test(evalStmt_assign_variable_pid) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(assign(a, pid), state(VarMap, ArrMap, IPs), 1, state(NewVarMap, ArrMap, NewIPs)),
    assertion(NewVarMap == [(a, 1), (b, 20), (c, 30)]),
    assertion(NewIPs == [1, 3, 3]).

test(evalStmt_assign_array_pid) :-
    test_state(VarMap, ArrMap, IPs),
    evalStmt(assign(array(arr, pid), 42), state(VarMap, ArrMap, IPs), 1, state(VarMap, NewArrMap, NewIPs)),
    assertion(NewArrMap == [(arr, [0, 42, 2, 3, 4]), (arr2, [10, 20, 30])]),
    assertion(NewIPs == [1, 3, 3]).

:- end_tests(verify).
