# Offline installed-package example

This example discovers `lib_desfire::core` through the installed CMake package.
It checks construction, argument validation and transport failure propagation
without a physical reader. It is a packaging smoke check, not protocol or
cryptographic qualification.

From the repository root after building and installing the core:

```sh
cmake -S examples/consumer -B build/consumer -DCMAKE_PREFIX_PATH=/absolute/path/to/install
cmake --build build/consumer --config Release --parallel
ctest --test-dir build/consumer -C Release --output-on-failure
```

For a shared build, make the installed library and OpenSSL runtime discoverable:
add `install/bin` to `PATH` on Windows, `install/lib` to `LD_LIBRARY_PATH` on Linux,
or `install/lib` to `DYLD_LIBRARY_PATH` on macOS. Adjust `lib` if your install uses
another library directory.
