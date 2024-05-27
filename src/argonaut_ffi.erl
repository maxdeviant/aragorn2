-module(argonaut_ffi).

-export([hash_password/2]).
-nifs([hash_password/2]).

-on_load(init/0).

init() ->
    ok = erlang:load_nif("./priv/argonaut/libargonaut_ffi", 0).

hash_password(_Hasher, _Password) ->
    erlang:nif_error(nif_library_not_loaded).
