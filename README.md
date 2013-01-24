# elli_cookie

A library application for reading, setting, and otherwise managing
cookies in [elli](https://github.com/knutin/elli).

## Usage

See the large test set in [`elli_cookie`](https://github.com/drfloob/elli_cookie/blob/master/src/elli_cookie.erl) for a more thorough set of usage examples.

### Basic Cookie Management and Cookie Option Settings

```erlang
%% in an elli callback module
handle(Req, _) ->
    Cookies = elli_cookie:parse(Req),

    %% retrieve a cookie value ...
    _PublicKey = elli_cookie:get("key", Cookies),
    %% ... and do something with it

    %% create new cookie for domain www.example.com that expires in 2 weeks
    FizzCookie = elli_cookie:new("fizz", "buzz", [elli_cookie:domain("www.example.com"), elli_cookie:expires({2, weeks})]),

    %% delete key cookie
    DeleteKeyCookie = elli_cookie:delete("key"),

    %% return response with cookies
    {ok, [DeleteKeyCookie, FizzCookie], "key deleted; fizz set"}.
```
