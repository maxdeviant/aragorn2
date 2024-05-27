build-nif:
    (cd native/argonaut && cargo build --release)
    cp native/argonaut/target/release/libargonaut_ffi.dylib ./priv/argonaut/libargonaut_ffi.so
