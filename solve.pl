% Hubert Michalski hm438596

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
        format('Error: brak pliku o nazwie - ~w~n', File)
    ).

verify(N, _) :-
    format('Error: parametr ~w powinien byc liczba > 0~n', N).

% initState(+Program, +N, -InitState)
initState(Program, N, InitState) :-
    Program = program(VarIdents, ArrIdents, _),
    initList(N, 1, IPs),
    initList(N, 0, InitArray),
    initMap(VarIdents, 0, VarMap),
    initMap(ArrIdents, InitArray, ArrMap),
    InitState = state(VarMap, ArrMap, IPs).

% TODO: dfs(+Program, +State)
dfs(Program, State).

% TODO: step(+Program, +State, +PrId, -NewState)
step(Program, State, PrId, NewState).

% TODO: evalStmt(+Statement, +State, +PrId, -NewState)
evalStmt(assign(VarId, Expr), State, PrId, NewState).

evalStmt(assign(array(ArrId, IndexExpr), Expr), State, PrId, NewState).

evalStmt(sekcja, State, PrId, NewState).

evalStmt(goto(IP), State, PrId, NewState).

evalStmt(condGoto(BExpr, IP), State, PrId, NewState).

% ==== Expression evaluation ====
% evalExpr(+Expr, +State, +PrId, -Value)
evalExpr(pid, _, PrId, PrId).

evalExpr(Expr, State, _, Value) :-
    evalExpr(Expr, State, Value).

% evalExpr(+Expr, +State, -Value)
evalExpr(Num, _, Value) :-
    integer(Num),
    Value is Num.

evalExpr(VarId, State, Value) :-
    atom(VarId),
    State = state(VarMap, _, _),
    get(VarId, VarMap, Value).

evalExpr(array(ArrId, IndexExpr), State, Value) :-
    State = state(_, ArrMap, _),
    evalExpr(IndexExpr, State, Index),
    get(ArrId, ArrMap, Array),
    nth0(Index, Array, Value).

% evalBExpr(+BExpr, +State)
evalBExpr(BExpr, State) :-
    BExpr =.. [Op, Expr1, Expr2],
    evalExpr(Expr1, State, Value1),
    evalExpr(Expr2, State, Value2),
    call(Op, Value1, Value2).

% ==== Utility functions ====
% initMap(+Idents, +Value, -Map)
initMap([], _, []).
initMap([Ident | RestIdents], Value, [(Ident, Value) | RestMap]) :-
    initMap(RestIdents, Value, RestMap).

% upsert(+Key, +Value, +Map, -NewMap)
upsert(Key, Value, Map, NewMap) :-
    ( select((Key, _), Map, Rest) ->
        NewMap = [(Key, Value) | Rest]
    ;
        NewMap = [(Key, Value) | Map]
    ).

% get(+Key, +VarMap, -Value)
get(Key, Map, Value) :-
    member((Key, Value), Map).

% initList(+N, +Value, -List)
initList(0, _, []).
initList(N, Value, [Value | Rest]) :-
    N > 0,
    N1 is N - 1,
    initList(N1, Value, Rest).

% insertAt(+Value, +Position, +List, -NewList)
insertAt(Value, 0, List, [Value | List]).
insertAt(Value, Position, [Start | Rest], [Start | NewRest]) :-
    Position > 0,
    NewPosition is Position - 1,
    insertAt(Value, NewPosition, Rest, NewRest).