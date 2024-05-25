% Hubert Michalski hm438596

% FIXME: REMOVE THIS
:- module(verify, [
    initMap/3,
    mapUpsert/4,
    mapGet/3,
    initList/3,
    listInsertAt/4,
    initState/3,
    evalExpr/4
]).

:- ensure_loaded(library(lists)).
:- op(700, xfx, '<>').

% program(VarIdents, ArrIdents, Statements)
% VarIdents - list of variable identifiers
% ArrIdents - list of array identifiers
% Statements - list of statements

% state(VarMap, ArrMap, IPs)
% VarMap - list of pairs (VarId, Value)
% ArrMap - list of pairs (ArrId, [Value1, Value2, ...])
% IPs - list of instruction pointers

% ==== Entry point ====
verify :-
    current_prolog_flag(argv, [StrN, FilePath]),
    atom_number(StrN, N),
    verify(N, FilePath).

verify :-
    format('Error: niepoprawne argumenty~n').

% ==== Program verification ====
% verify(+N, +FilePath)
verify(N, FilePath) :-
    integer(N),
    N >= 1,
    set_prolog_flag(fileerrors, off),
    ( see(FilePath) ->
        read(variables(VarIdents)),
        read(arrays(ArrIdents)),
        read(program(Statements)),
        seen,
        Program = program(VarIdents, ArrIdents, Statements),
        initState(Program, N, InitState),
        dfs(Program, InitState)
    ;
        format('Error: brak pliku o nazwie - ~w~n', FilePath)
    ).

verify(N, _) :-
    format('Error: parametr ~w powinien byc liczba > 0~n', N).

% initState(+Program, +N, -InitState)
initState(program(VarIdents, ArrIdents, _), N, state(VarMap, ArrMap, IPs)) :-
    initList(N, 1, IPs),
    initList(N, 0, InitArray),
    initMap(VarIdents, 0, VarMap),
    initMap(ArrIdents, InitArray, ArrMap).

% TODO: dfs(+Program, +State)
dfs(_, _).

% step(+Program, +State, +PrId, -NewState)
step(program(_, _, Statements), state(VarMap, ArrMap, IPs), PrId, NewState) :-
    nth0(PrId, IPs, IP),
    nth1(IP, Statements, Statement),
    evalStmt(Statement, state(VarMap, ArrMap, IPs), PrId, NewState).

% ==== Statement evaluation ====
evalStmt(assign(VarId, Expr), state(VarMap, ArrMap, IPs), PrId, state(NewVarMap, ArrMap, NewIPs)) :-
    atom(VarId),
    evalExpr(Expr, state(VarMap, ArrMap, IPs), Value),
    mapUpsert(VarId, Value, VarMap, NewVarMap),
    incrementIP(PrId, IPs, NewIPs).

evalStmt(assign(array(ArrId, IndexExpr), Expr), state(VarMap, ArrMap, IPs), PrId, state(VarMap, NewArrMap, NewIPs)) :-
    evalExpr(IndexExpr, state(VarMap, ArrMap, IPs), Index),
    evalExpr(Expr, state(VarMap, ArrMap, IPs), Value),
    mapGet(ArrId, ArrMap, Array),
    listInsertAt(Value, Index, Array, NewArray),
    mapUpsert(ArrId, NewArray, ArrMap, NewArrMap),
    incrementIP(PrId, IPs, NewIPs).

evalStmt(sekcja, state(VarMap, ArrMap, IPs), PrId, state(VarMap, ArrMap, NewIPs)) :-
    incrementIP(PrId, IPs, NewIPs).

evalStmt(goto(NewIP), state(VarMap, ArrMap, IPs), PrId, state(VarMap, ArrMap, NewIPs)) :-
    listInsertAt(NewIP, PrId, IPs, NewIPs).

evalStmt(condGoto(BExpr, NewIP), state(VarMap, ArrMap, IPs), PrId, NewState) :-
    ( evalBExpr(BExpr, state(VarMap, ArrMap, IPs)) ->
        evalStmt(goto(NewIP), state(VarMap, ArrMap, IPs), PrId, NewState)
    ;
        incrementIP(PrId, IPs, NewIPs),
        NewState = state(VarMap, ArrMap, NewIPs)
    ).

% incrementIP(+PrId, +IPs, -NewIPs)
incrementIP(PrId, IPs, NewIPs) :-
    nth0(PrId, IPs, IP),
    NewIP is IP + 1,
    listInsertAt(NewIP, PrId, IPs, NewIPs).

% ==== Expression evaluation ====
% evalExpr(+Expr, +State, +PrId, -Value)
evalExpr(pid, _, PrId, PrId) :- !.

evalExpr(Num, _, _, Value) :-
    integer(Num),
    Value is Num, !.

evalExpr(VarId, state(VarMap, _, _), _, Value) :-
    atom(VarId),
    mapGet(VarId, VarMap, Value), !.

evalExpr(array(ArrId, IndexExpr), State, PrId, Value) :-
    evalExpr(IndexExpr, State, PrId, Index),
    State = state(_, ArrMap, _),
    mapGet(ArrId, ArrMap, Array),
    nth0(Index, Array, Value), !.

evalExpr(Expr, State, PrId, Value) :-
    Expr =.. [Op, Expr1, Expr2],
    member(Op, [+, -, *, /]),
    evalExpr(Expr1, State, PrId, Value1),
    evalExpr(Expr2, State, PrId, Value2),
    Eval =.. [Op, Value1, Value2],
    Value is Eval, !.

% evalBExpr(+BExpr, +State, +PrId)
evalBExpr(BExpr, State, PrId) :-
    BExpr =.. [Op, Expr1, Expr2],
    evalExpr(Expr1, State, PrId, Value1),
    evalExpr(Expr2, State, PrId, Value2),
    call(Op, Value1, Value2).

% ==== Utility functions ====
% initMap(+Idents, +Value, -Map)
initMap([], _, []).
initMap([Ident | RestIdents], Value, [(Ident, Value) | RestMap]) :-
    initMap(RestIdents, Value, RestMap).

% mapUpsert(+Key, +Value, +Map, -NewMap)
mapUpsert(Key, Value, Map, NewMap) :-
    ( select((Key, _), Map, Rest) ->
        NewMap = [(Key, Value) | Rest]
    ;
        NewMap = [(Key, Value) | Map]
    ).

% mapGet(+Key, +VarMap, -Value)
mapGet(Key, Map, Value) :-
    member((Key, Value), Map), !.

% initList(+N, +Value, -List)
initList(0, _, []) :- !.
initList(N, Value, [Value | Rest]) :-
    N > 0,
    N1 is N - 1,
    initList(N1, Value, Rest).

% listInsertAt(+Value, +Position, +List, -NewList)
listInsertAt(Value, 0, [_ | Rest] ,[Value | Rest]) :- !.
listInsertAt(Value, Position, [Start | Rest], [Start | NewRest]) :-
    Position > 0,
    NewPosition is Position - 1,
    listInsertAt(Value, NewPosition, Rest, NewRest).
