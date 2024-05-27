-module(aragorn2_ffi).

-export([hash_password/2, verify_password/3]).
-nifs([hash_password/2, verify_password/3]).

-on_load(init/0).

init() ->
    ok = erlang:load_nif("./priv/aragorn2/libaragorn2_ffi", 0).

hash_password(_Hasher, _Password) ->
    erlang:nif_error(nif_library_not_loaded).

verify_password(_Hasher, _CandidatePassword, _HashedPassword) ->
    erlang:nif_error(nif_library_not_loaded).
