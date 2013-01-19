%%%-------------------------------------------------------------------
%%% @author aj heller <aj@drfloob.com>
%%% @copyright (C) 2012, aj heller
%%% @doc A library module for reading and managing cookies in elli.
%%% @end
%%% Created :  3 Oct 2012 by aj heller <aj@drfloob.com>
%%%-------------------------------------------------------------------
-module(elli_cookie).

-export([parse/1, get/2, get/3, new/2, new/3, delete/1]).
-export([expires/1, path/1, domain/1, secure/0, http_only/0]).

-include_lib("elli/include/elli.hrl").

-type stringy() :: string() | binary().
-type cookie() :: {binary(), binary()}.
-type cookie_list() :: [cookie()].
-type cookie_option() :: {atom(), string()}.


%% returns a proplist made from the submitted cookies
-spec parse(Req :: #req{}) -> no_cookies | cookie_list().
parse(Req = #req{}) ->
    tokenize(elli_request:get_header(<<"Cookie">>, Req)).


%% gets a specific cookie value from the set of parsed cookie
-spec get(Key :: binary(), Cookies :: cookie_list()) -> undefined | binary().
get(_, no_cookies) ->
    undefined;
get(Key, Cookies) ->
    ok = valid_cookie(Key),
    proplists:get_value(to_bin(Key), Cookies).

-spec get(Key :: binary(), Cookies :: cookie_list(), Default) -> Default | binary().
get(_, no_cookies, Default) ->
    Default;
get(Key, Cookies, Default) ->
    ok = valid_cookie(Key),
    proplists:get_value(to_bin(Key), Cookies, Default).

%% creates a new cookie in a format appropriate for server response
-spec new(Name :: stringy(), Value :: stringy()) -> cookie().
new(Name, Value) ->
    ok = valid_cookie(Name),
    ok = valid_cookie(Value),
    BName = to_bin(Name),
    BVal = to_bin(Value),
    {<<"Set-Cookie">>, <<BName/binary, "=", BVal/binary>>}.

-spec new(Name :: stringy(), Value :: stringy(), Options :: [cookie_option()]) -> cookie().
new(Name, Value, Options) ->
    ok = valid_cookie(Name),
    ok = valid_cookie(Value),
    BName = to_bin(Name),
    BValue = to_bin(Value),
    Bin = <<BName/binary,"=",BValue/binary>>,
    FinalBin = lists:foldl(fun set_cookie_attribute/2, Bin, Options),
    {<<"Set-Cookie">>, FinalBin}.

%% Creates a header that will delete a specific cookie on the client
-spec delete(Name :: stringy()) -> cookie().
delete(Name) ->
    ok = valid_cookie(Name),
    new(Name, "", [expires({{1970,1,1},{0,0,0}})]).



%%------------------------------------------------------------
%% Cookie Option helpers
%%------------------------------------------------------------

%% set a path for a cookie
path(P) ->
    {path, P}.
%% set a domain for a cookie
domain(P) ->
    {domain, P}.
%% make the cookie secure (SSL)
secure() ->
    secure.
%% make an http-only cookie
http_only() ->
    http_only.



%% set cookie expiration
expires({S, seconds}) ->
    expires_plus(S);
expires({M, minutes}) ->
    expires_plus(M*60);
expires({H, hours}) ->
    expires_plus(H*60*60);
expires({D, days}) ->
    expires_plus(D*24*60*60);
expires({W, weeks}) ->
    expires_plus(W*7*24*60*60);
expires(Date) ->
    {expires, httpd_util:rfc1123_date(Date)}.



%%------------------------------------------------------------
%% Internal
%%------------------------------------------------------------


to_bin(B) when is_binary(B) ->
    B;
to_bin(L) when is_list(L) ->
    list_to_binary(L);
to_bin(X) ->
    throw({error, {not_a_string, X}}).



tokenize(<<>>) ->
    [];
tokenize(CookieStr) when is_binary(CookieStr) ->
    Cookies = binary:split(CookieStr, <<";">>, [trim, global]),
    lists:map(fun tokenize2/1, Cookies);
tokenize(_) ->
    no_cookies.

tokenize2(NVP) ->
    [N,V] = binary:split(NVP, <<"=">>, [trim]),
    {strip_bin(N), strip_bin(V)}.
    %% {N, V}.
    


set_cookie_attribute({expires, Exp}, Bin) ->
    BExp = to_bin(Exp),
    <<Bin/binary, ";Expires=", BExp/binary>>;
set_cookie_attribute({path, Path}, Bin) ->
    BPath = to_bin(Path),
    <<Bin/binary, ";Path=", BPath/binary>>;
set_cookie_attribute({domain, Domain}, Bin) ->
    BDomain = to_bin(Domain),
    <<Bin/binary, ";Domain=", BDomain/binary>>;
set_cookie_attribute(secure, Bin) ->
    <<Bin/binary, ";Secure">>;
set_cookie_attribute(http_only, Bin) ->
    <<Bin/binary, ";HttpOnly">>;
set_cookie_attribute(X, _) ->
    throw({error, {invalid_cookie_attribute, X}}).



expires_plus(N) ->
    UT = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    UTE = UT + N,
    Date = calendar:gregorian_seconds_to_datetime(UTE),
    {expires, httpd_util:rfc1123_date(Date)}.
    



strip_bin(B) ->
    list_to_binary(string:strip(binary_to_list(B))).



%%------------------------------------------------------------
%% Predicates
%%------------------------------------------------------------

valid_cookie(B) when is_binary(B) ->
    Str = binary_to_list(B),
    valid_cookie2(string:str(Str, "="), B);
valid_cookie(N) when is_list(N) ->
    valid_cookie2(string:str(N, "="), N);
valid_cookie(X) ->
    {invalid_cookie, X}.

valid_cookie2(0, _) -> ok;
valid_cookie2(_, N) -> {invalid_cookie, N}.
    


%%------------------------------------------------------------
%% Tests
%%------------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parse_test_() ->
    [?_assertError(function_clause, parse(#req{}))
    , ?_assertError({badmatch, _}, parse(#req{headers=[{<<"Cookie">>, <<"1=">>}]}))

    , ?_assertEqual(no_cookies, parse(#req{headers=[]}))
    , ?_assertEqual([{<<"1">>, <<"2">>}], parse(#req{headers=[{<<"Cookie">>, <<"1=2">>}]}))
    , ?_assertEqual([{<<"1">>, <<"2">>}, {<<"3">>, <<"4">>}], parse(#req{headers=[{<<"Cookie">>, <<"1=2; 3=4">>}]}))
    , ?_assertEqual([{<<"1">>, <<"2">>}, {<<"3">>, <<"4">>}, {<<"five">>, <<"six">>}]
		    , parse(#req{headers=[{<<"Cookie">>, <<"1=2; 3=4; five   =    six">>}]}))
    ].

get_test_() ->
    Cookies = [{<<"1">>, <<"two">>}, {<<"three">>, <<"4">>}],
    [?_assertEqual(undefined, get("nope", []))
     , ?_assertEqual(undefined, get("nope", Cookies))
     , ?_assertEqual(<<"two">>, get("1", Cookies))
     , ?_assertEqual(<<"two">>, get(<<"1">>, Cookies))
     , ?_assertEqual(undefined, get(<<"4">>, Cookies))
     , ?_assertEqual(nope, get(<<"4">>, Cookies, nope))
     , ?_assertError({badmatch, {invalid_cookie, <<"4=">>}}, get(<<"4=">>, Cookies, nope))
    ].


get_noCookies_test_() ->
    [?_assertEqual(undefined, get("x", no_cookies))
     , ?_assertEqual(undefined, get("x", no_cookies, undefined))
     , ?_assertEqual(bort, get("x", no_cookies, bort))
    ].


new_test_() ->
    [
     ?_assertMatch({<<"Set-Cookie">>, <<"name=val">>}, new("name", "val"))
     , ?_assertMatch({<<"Set-Cookie">>, <<"name=val">>}, new(<<"name">>, <<"val">>))
     , ?_assertError({badmatch, {invalid_cookie, bork}}, new(<<"name">>, bork))
     , ?_assertError({badmatch, {invalid_cookie, bork}}, new(bork, "val"))
     , ?_assertError({badmatch, {invalid_cookie, "val="}}, new("name", "val="))
     , ?_assertError({badmatch, {invalid_cookie, <<"val=">>}}, new("name", <<"val=">>))
     , ?_assertError({badmatch, {invalid_cookie, "name="}}, new("name=", "val"))
     , ?_assertError({badmatch, {invalid_cookie, <<"name=">>}}, new(<<"name=">>, "val"))

     %% be careful: binaries are not checked for stringyness
     , ?_assertMatch(_, new(<<1>>, "val"))

     , ?_assertThrow({error, {invalid_cookie_attribute, domain}}, new("n", "v", [domain, "/"]))
     , ?_assertMatch({_, <<"n=v;Domain=www.example.com">>}, new("n", "v", [domain("www.example.com")]))
     , ?_assertMatch({_, <<"n=v;Path=/">>}, new("n", "v", [path("/")]))
     , ?_assertMatch({_, <<"n=v;Secure">>}, new("n", "v", [secure()]))
     , ?_assertMatch({_, <<"n=v;HttpOnly">>}, new("n", "v", [http_only()]))

     , ?_assertMatch({_, <<"n=v;Expires=", _/binary>>}, new("n", "v", [expires({2,seconds})]))
     , ?_assertMatch({_, <<"n=v;Expires=", _/binary>>}, new("n", "v", [expires({2,minutes})]))
     , ?_assertMatch({_, <<"n=v;Expires=", _/binary>>}, new("n", "v", [expires({2,hours})]))
     , ?_assertMatch({_, <<"n=v;Expires=", _/binary>>}, new("n", "v", [expires({2,days})]))
     , ?_assertMatch({_, <<"n=v;Expires=", _/binary>>}, new("n", "v", [expires({2,weeks})]))

     , ?_assertMatch({_, <<"n=v;Expires=", _/binary>>}, new("n", "v", [expires(calendar:local_time())]))
     , ?_assertMatch({_, <<"n=v;Expires=Fri, 21 Mar 2014", _/binary>>}, new("n", "v", [expires({{2014,03,21},{16,20,42}})]))

     %% be careful: cookie options are not thoroughly sanity checked.
     , ?_assertMatch({_, <<"n=v;Domain=/">>}, new("n", "v", [domain("/")]))
    ].


delete_test_() ->
    [
     ?_assertError({badmatch, {invalid_cookie, bork}}, delete(bork))
     , ?_assertError({badmatch, {invalid_cookie, 1}}, delete(1))
     , ?_assertError({badmatch, {invalid_cookie, "="}}, delete("="))

     , ?_assertMatch({_, <<"test=;Expires=Thu, 01 Jan 1970", _/binary>>}, delete("test"))
     , ?_assertMatch({_, <<"test=;Expires=Thu, 01 Jan 1970", _/binary>>}, delete(<<"test">>))
     , ?_assertError({badmatch, {invalid_cookie, <<"=">>}}, delete(<<"=">>))
    ].


valueHasEqual_test_() ->
    [
     ?_assertMatch({<<"Set-Cookie">>, <<"name=val=3">>}, new("name", "val=3"))
     , ?_assertEqual([{<<"name">>, <<"val=3">>}], parse(#req{headers=[{<<"Cookie">>, <<"name=val=3">>}]}))
     , ?_assertMatch({<<"val=3">>}, get("name", [{<<"name">>, <<"val=3">>}]))
    ].


-endif.
