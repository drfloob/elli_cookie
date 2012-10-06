%%%-------------------------------------------------------------------
%%% @author aj <AJ Heller <aj@drfloob.com>>
%%% @copyright (C) 2012, aj
%%% @doc
%%%
%%% @end
%%% Created :  3 Oct 2012 by aj <AJ Heller <aj@drfloob.com>>
%%%-------------------------------------------------------------------
-module(elli_cookie).

-export([parse/1, get/2, get/3, new/2, new/3, delete/1]).
-export([expires/1, path/1, domain/1, secure/0, http_only/0]).

-include_lib("elli/include/elli.hrl").


parse(#req{} = Req) ->
    tokenize(elli:get_header(<<"Cookie">>, Req, [])).


get(Key, Cookies) ->
    proplists:get(Key, Cookies).
get(Key, Cookies, Default) ->
    proplists:get(Key, Cookies, Default).


new(Name, Value) ->
    BName = to_bin(Name),
    BVal = to_bin(Value),
    {<<"Set-Cookie">>, <<BName/binary, "=", BVal/binary>>}.
new(Name, Value, Options) ->
    BName = to_bin(Name),
    BValue = to_bin(Value),
    Bin = <<BName/binary,"=",BValue/binary>>,
    FinalBin = lists:foldl(fun set_cookie_attribute/2, Bin, Options),
    {<<"Set-Cookie">>, FinalBin}.


delete(Name) ->
    new(Name, "", [expires({{1970,1,1},{0,0,0}})]).

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
tokenize(CookieStr) ->
    Cookies = binary:split(CookieStr, <<";">>),
    lists:map(fun tokenize2/1, Cookies).

tokenize2(NVP) ->
    [N,V] = binary:split(NVP, <<"=">>),
    {N, V}.
    


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



path(P) ->
    {path, P}.
domain(P) ->
    {domain, P}.
secure() ->
    secure.
http_only() ->
    http_only.



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


expires_plus(N) ->
    UT = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    UTE = UT + N,
    Date = calendar:gregorian_seconds_to_datetime(UTE),
    {expires, httpd_util:rfc1123_date(Date)}.
    


