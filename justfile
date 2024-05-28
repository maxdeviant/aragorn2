build-nif:
    (cd native/aragorn2 && cargo build --release)
    cp native/aragorn2/target/release/libaragorn2_ffi.dylib ./priv/lib/aragorn2_ffi.so
