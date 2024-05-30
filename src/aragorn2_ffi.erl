-module(aragorn2_ffi).

-export([hash_password/2, verify_password/3]).
-nifs([hash_password/2, verify_password/3]).

-on_load(init/0).

init() ->
    ok = erlang:load_nif(nif_filepath(), 0).

nif_filepath() ->
    DllName = case {os(), arch()} of
        {macos, aarch64} -> "aragorn2_ffi-macos-aarch64";
        {Os, Arch} -> throw({dll_not_found, ["Unsupported platform", Os, Arch]})
    end,
    filename:join([code:priv_dir("aragorn2"), "lib", DllName]).

os() ->
    case os:type() of
        {unix, linux} -> linux;
        {unix, darwin} -> macos;
        {win32, nt} -> windows;
        {_, Other} -> {other, atom_to_binary(Other, utf8)}
    end.

arch() ->
    SystemArchitecture = erlang:system_info(system_architecture),
    case string:split(SystemArchitecture, "-") of
        ["x86_64", _] -> x86_64;
        ["aarch64", _] -> aarch64;
        Other -> {other, Other}
    end.

hash_password(_Hasher, _Password) ->
    erlang:nif_error(nif_library_not_loaded).

verify_password(_Hasher, _CandidatePassword, _HashedPassword) ->
    erlang:nif_error(nif_library_not_loaded).
