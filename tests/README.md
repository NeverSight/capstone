# Testing in Capstone

## Running tests

### Types of test and their location

_YAML test files_

These test files are consumed by the various `cstest` tools.
They contain all detail tests. As well as the LLVM regression tests (`MC` tests).

Directories group tests by the category they intent to test.

_Legacy (integration)_

Legacy tests which only printed to `stdout`. In practice they only test if the code segfaults.
Checking the produced output was not implemented.

The x87 environment API and native memory-access tests report a CTest skip
when `CAPSTONE_X86_REDUCE` omits those instructions. The native test also skips
on unsupported hosts or under instruction translation; the API test still
runs in full builds on any host.

`unit_x86_call_target` compares the private direct-CALL query with full operand
detail across bitness/vendor modes, both syntaxes, prefix pairs, REX2 payloads,
truncations, wrapped addresses and malformed input. It also checks option
independence and untouched output on rejection. `unit_x86_buffer_bounds` places
complete and truncated calls immediately before an inaccessible page. It also
checks byte copies of lengths 1..15 in every x86 mode and text/detail setting,
including the iterator's untouched output tail and allocated-array results.
With the private adapter enabled, `unit_x86_scan_adapter` checks every accepted
length and rejection of a 16-byte result even when 16 input bytes are available.

`unit_x86_scan_batch` checks source-extension precedence (including mixed mode
flags), bounded output against iteration, and explicit
public IDs against the iterator and allocated-array API in all three bitness
modes. Cases include grouped opcodes, size prefixes and invalid ModR/M forms.

`unit_x86_immediate_size` compares both immediate sizes against the original
metadata for every 16-bit opcode ID, holes and larger unknown IDs. It checks
both optional-output forms in full and reduced builds. The generator check
detects stale indices after either instruction enum or the metadata changes.

`unit_sstream` covers bounded token appends, including truncation, markup,
self-appends and a source immediately preceding the stream. Such a source can
end at the first output byte, so its length must be determined before writing.
String replacement checks include empty replacements, appending at an earlier
terminator, replacement text borrowed from the stream, and the final-byte
capacity boundary.

### Testing tools and usage

The CI DIET jobs build every backend in Release with GCC and Clang and retain
the normal warning-as-error flags. To reproduce the library build locally:

```bash
cmake -S . -B build-diet -DCMAKE_BUILD_TYPE=Release \
  -DCAPSTONE_BUILD_DIET=ON -DCAPSTONE_BUILD_SHARED_LIBS=ON \
  -DCAPSTONE_BUILD_STATIC_LIBS=ON -DCAPSTONE_BUILD_CSTEST=OFF \
  -DCAPSTONE_BUILD_LEGACY_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF
cmake --build build-diet --target capstone_shared capstone_static
```

#### `cstest`

`cstest` is the testing tool written in C. It is implemented in `suite/cstest/`
It consumes the `yaml` files and reports errors or mismatches for disassembled instructions and their details.

**Building**

> _Dependencies:_ `cstest` requires the `libyaml` library.

You build `cstest` by adding the `-DCAPSTONE_BUILD_CSTEST=1` option during configuration of the Capstone build.

If you build and install Capstone `cstest` gets installed as well.
Otherwise you find it in the build directory.

```bash
# Install libyaml
# sudo apt install libyaml-dev
# or
# sudo dnf install libyaml-devel
cd "<capstone-repo-root>"
# Optionally add the `-DENABLE_ASAN=1` flag.
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCAPSTONE_BUILD_CSTEST=ON
cmake --build build --config Debug
cmake --install build --prefix "<install-prefix>"
```

Run the integration tests for `cstest` itself

```bash
./suite/cstest/test/integration_tests.py cstest
```

**Run the tests**

```bash
# Check supported options
cstest -h
# Run all
cstest tests/
```

Alternatively, you can use the `CMake` test manager.

```bash
# List available tests
ctest --test-dir build -N
# Run a specific test
ctest --test-dir build -R "<name>"
```

#### `cstest_py`

`cstest_py` is the testing tool written in Python. It is implemented in `bindings/python/cstest_py`
It consumes the `yaml` files and reports errors or mismatches for disassembled instructions and their details.

**Installing**

You need to install the Capstone Python bindings first and afterwards the `cstest_py`.

```bash
# Optionally, create a new virtual environment
python3 -m venv .venv
source .venv/bin/activate

cd bindings/python
pip install -e .
pip install -e cstest_py
cd ../..
```

Run the integration tests for `cstest_py` itself

```bash
./suite/cstest/test/integration_tests.py cstest_py
```

And run the tests

```bash
# Check supported options
cstest_py -h
# Run all
cstest_py tests/
```

## Add new tests

### Unit and integration tests

Add the source into `test/integration` or `test/unit` respectively and update the `CMakeLists.txt` file.

### YAML

There are very few fields which are mandatory to fill.
Check `suite/cstest/test/min_valid_test_file.yaml` to see which one.

- In general it is useful to just copy a previous test file and rewrite it accordingly.
- If you assign C enumeration identifiers to some fields (to check enumeration values),
ensure they are added on the `suite/cstest/include/test_mapping.h`. Otherwise, `cstest` cannot map the strings
to the values for comparison.
- Rarely used, but useful fields are: `name`, `skip`, `skip_reason`.

> [!IMPORTANT]
> Boolean values in the YAML files are encoded like the following:
> ```yaml
> # 1  = true
> # 0  = unset
> # -1 = false
>
> is_alias: 1 # Equivalent to is_alias: true
> is_alias: 0 # Equivalent to an unset is_alias field
> is_alias: -1 # Equivalent to is_alias: false
> ```
> The reason is the C library parsing the YAML files.
> It sets all unset (not present) fields to 0.

#### MC regression tests

The `MCUpdater` translates most test files of the LLVM MC regression tests into our YAML files.

The LLVM regression tests, check the bytes and assembly for all instructions of an architecture.
They do it by passing bytes or assembly to the `llvm-mc` and `FileCheck` tool and compare the output.
We capture this output and process it into YAML.
So you need to install `llvm-mc` and `FileCheck` for our updater to work.

To update the YAML MC regression tests, you need to install `Auto-Sync` and run the `MCUpdater`.

```bash
cd suite/auto-sync/
# Follow install instructions of Auto-Sync described in the README
# And run the updater:
./src/autosync/MCUpdater.py -a ARCH
ls build/mc_out/
# The produce yaml files. Copy them manually to tests/MC/ARCH
```

**Please note:**

Each of the LLVM test files can contain several `llvm-mc` commands to run on the same file.
This is done to test the same file with different CPU features enabled.
So it can test different assembly flavors etc.

In Capstone all modules enable always all CPU features (even if this is not
possible in reality).
Due to this, we always parse all `llvm-mc` commands but only write the last version of them to disk.
So if the same test file is tested with three different features enables, once with `FeatureA`, `FeatureB` and `FeatureC`
we only save the output with `FeatureC` enabled.

This might give you MC test files which fail due to valid but mismatching disassembly.
You can set the `skip` field for those tests and add a `skip_reason`.

Once https://github.com/capstone-engine/capstone/issues/1992 is resolved, we can
test all variants.
