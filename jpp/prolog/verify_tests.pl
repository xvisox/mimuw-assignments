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

% Test mapUpdate/4
test(update_existing_pair) :-
    mapUpdate(a, 2, [(a, 1)], NewMap),
    assertion(NewMap == [(a, 2)]).

test(update_existing_pair_non_empty) :-
    mapUpdate(a, 2, [(a, 1), (b, 3)], NewMap),
    assertion(NewMap == [(a, 2), (b, 3)]).

test(update_at_beginning) :-
    mapUpdate(a, 5, [(a, 1), (b, 2)], NewMap),
    assertion(NewMap == [(a, 5), (b, 2)]).

test(update_in_middle) :-
    mapUpdate(b, 5, [(a, 1), (b, 2), (c, 3)], NewMap),
    assertion(NewMap == [(a, 1), (b, 5), (c, 3)]).

test(update_at_end) :-
    mapUpdate(c, 5, [(a, 1), (b, 2), (c, 3)], NewMap),
    assertion(NewMap == [(a, 1), (b, 2), (c, 5)]).

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

% Test listUpdate/4
test(listUpdate_start) :-
    listUpdate(x, 0, [a, b, c], NewList),
    assertion(NewList == [x, b, c]).

test(listUpdate_middle) :-
    listUpdate(x, 2, [a, b, c, d], NewList),
    assertion(NewList == [a, b, x, d]).

test(listUpdate_end) :-
    listUpdate(x, 3, [a, b, c, d], NewList),
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
    assertion(NewArrMap == [(arr, [0, 1, 2, 3, 4]), (arr2, [10, 42, 30])]),
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

% Even newer state used in tests
test_state_step(VarMap, ArrMap, IPs) :-
    VarMap = [(a, 10), (b, 20), (c, 30)],
    ArrMap = [(arr, [0, 1, 2, 3, 4]), (arr2, [10, 20, 30])],
    IPs = [1, 1, 1].

% Test step/4
test(step_assign_variable) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [assign(a, 42)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(NewVarMap, ArrMap, NewIPs)),
    assertion(NewVarMap == [(a, 42), (b, 20), (c, 30)]),
    assertion(NewIPs == [1, 2, 1]).

test(step_assign_array) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [assign(array(arr, 2), 42)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, NewArrMap, NewIPs)),
    assertion(NewArrMap == [(arr, [0, 1, 42, 3, 4]), (arr2, [10, 20, 30])]),
    assertion(NewIPs == [1, 2, 1]).

test(step_sekcja) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [sekcja]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 2, 1]).

test(step_goto) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [goto(5)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 5, 1]).

test(step_condGoto_true) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [condGoto(b > a, 5)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 5, 1]).

test(step_condGoto_false) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [condGoto(b < a, 5)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, ArrMap, NewIPs)),
    assertion(NewIPs == [1, 2, 1]).

test(step_assign_nested_array) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [assign(array(arr2, array(arr, 1)), 42)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, NewArrMap, NewIPs)),
    assertion(NewArrMap == [(arr, [0, 1, 2, 3, 4]), (arr2, [10, 42, 30])]),
    assertion(NewIPs == [1, 2, 1]).

test(step_assign_variable_pid) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [assign(a, pid)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(NewVarMap, ArrMap, NewIPs)),
    assertion(NewVarMap == [(a, 1), (b, 20), (c, 30)]),
    assertion(NewIPs == [1, 2, 1]).

test(step_assign_array_pid) :-
    test_state_step(VarMap, ArrMap, IPs),
    Program = program([], [], [assign(array(arr, pid), 42)]),
    step(Program, state(VarMap, ArrMap, IPs), 1, state(VarMap, NewArrMap, NewIPs)),
    assertion(NewArrMap == [(arr, [0, 42, 2, 3, 4]), (arr2, [10, 20, 30])]),
    assertion(NewIPs == [1, 2, 1]).

% Helper predicate to create a program and initialize state
create_complex_state(Statements, N, state(VarMap, ArrMap, IPs)) :-
    Program = program([x, y], [arr], Statements),
    initState(Program, N, state(VarMap, ArrMap, IPs)).

% Test step/4
test(step_multiple_threads) :-
    % Define the program statements
    Statements = [
        assign(x, 10),              % 1
        assign(array(arr, 0), 20),  % 2
        condGoto(x > 5, 5),         % 3
        assign(y, 30),              % 4
        sekcja,                     % 5
        goto(1)                     % 6
    ],

    % Initialize the state with 3 threads
    create_complex_state(Statements, 3, InitState),

    % Step 1: Thread 1 - assign(x, 10)
    step(program([x, y], [arr], Statements), InitState, 0, State1),
    state(VarMap1, ArrMap1, IPs1) = State1,
    assertion(VarMap1 == [(x, 10), (y, 0)]),
    assertion(IPs1 == [2, 1, 1]),

    % Step 2: Thread 2 - assign(x, 10)
    step(program([x, y], [arr], Statements), State1, 1, State2),
    state(VarMap2, ArrMap2, IPs2) = State2,
    assertion(VarMap2 == [(x, 10), (y, 0)]),
    assertion(IPs2 == [2, 2, 1]),

    % Step 3: Thread 3 - assign(x, 10)
    step(program([x, y], [arr], Statements), State2, 2, State3),
    state(VarMap3, ArrMap3, IPs3) = State3,
    assertion(VarMap3 == [(x, 10), (y, 0)]),
    assertion(IPs3 == [2, 2, 2]),

    % Step 4: Thread 1 - assign(array(arr, 0), 20)
    step(program([x, y], [arr], Statements), State3, 0, State4),
    state(VarMap4, ArrMap4, IPs4) = State4,
    assertion(ArrMap4 == [(arr, [20, 0, 0])]),
    assertion(IPs4 == [3, 2, 2]),

    % Step 5: Thread 2 - assign(array(arr, 0), 20)
    step(program([x, y], [arr], Statements), State4, 1, State5),
    state(VarMap5, ArrMap5, IPs5) = State5,
    assertion(ArrMap5 == [(arr, [20, 0, 0])]),
    assertion(IPs5 == [3, 3, 2]),

    % Step 6: Thread 3 - assign(array(arr, 0), 20)
    step(program([x, y], [arr], Statements), State5, 2, State6),
    state(VarMap6, ArrMap6, IPs6) = State6,
    assertion(ArrMap6 == [(arr, [20, 0, 0])]),
    assertion(IPs6 == [3, 3, 3]),

    % Step 7: Thread 1 - condGoto(>(x, 5), 5) - condition true
    step(program([x, y], [arr], Statements), State6, 0, State7),
    state(VarMap7, ArrMap7, IPs7) = State7,
    assertion(IPs7 == [5, 3, 3]),

    % Step 8: Thread 2 - condGoto(>(x, 5), 5) - condition true
    step(program([x, y], [arr], Statements), State7, 1, State8),
    state(VarMap8, ArrMap8, IPs8) = State8,
    assertion(IPs8 == [5, 5, 3]),

    % Step 9: Thread 3 - condGoto(>(x, 5), 5) - condition true
    step(program([x, y], [arr], Statements), State8, 2, State9),
    state(VarMap9, ArrMap9, IPs9) = State9,
    assertion(IPs9 == [5, 5, 5]),

    % Step 10: Thread 1 - sekcja
    step(program([x, y], [arr], Statements), State9, 0, State10),
    state(VarMap10, ArrMap10, IPs10) = State10,
    assertion(IPs10 == [6, 5, 5]),

    % Step 11: Thread 2 - sekcja
    step(program([x, y], [arr], Statements), State10, 1, State11),
    state(VarMap11, ArrMap11, IPs11) = State11,
    assertion(IPs11 == [6, 6, 5]),

    % Step 12: Thread 3 - sekcja
    step(program([x, y], [arr], Statements), State11, 2, State12),
    state(VarMap12, ArrMap12, IPs12) = State12,
    assertion(IPs12 == [6, 6, 6]),

    % Step 13: Thread 1 - goto(1)
    step(program([x, y], [arr], Statements), State12, 0, State13),
    state(VarMap13, ArrMap13, IPs13) = State13,
    assertion(IPs13 == [1, 6, 6]),

    % Step 14: Thread 2 - goto(1)
    step(program([x, y], [arr], Statements), State13, 1, State14),
    state(VarMap14, ArrMap14, IPs14) = State14,
    assertion(IPs14 == [1, 1, 6]),

    % Step 15: Thread 3 - goto(1)
    step(program([x, y], [arr], Statements), State14, 2, State15),
    state(VarMap15, ArrMap15, IPs15) = State15,
    assertion(IPs15 == [1, 1, 1]).

:- end_tests(verify).
