%%% @doc
%%% simple v tutorial: svt
%%%
%%% This module is currently named `svt', but you may want to change that.
%%% Remember that changing the name in `-module()' below requires renaming
%%% this file, and it is recommended to run `zx update .app` in the main
%%% project directory to make sure the ebin/svt.app file stays in
%%% sync with the project whenever you add, remove or rename a module.
%%% @end

-module(svt).
-vsn("0.1.0").


-license("MIT").

-export([start/1]).


-spec start(ArgV) -> ok
    when ArgV :: [string()].

start(ArgV) ->
    ok = io:format("Hello, World! Args: ~tp~n", [ArgV]),
    zx:silent_stop().
