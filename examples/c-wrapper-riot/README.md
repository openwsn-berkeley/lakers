First, go to the top level directory and generate the headers and static library:

```bash
./build_for_c.sh rust-cryptocell310 # or rust-psa-baremetal
```

Then, compile and flash to the board (default is nRF52840):

With `rust-cryptocell310`:

```bash
make flash term
```

With `rust-psa-baremetal`:

```bash
make flash term EDHOC_CRYPTO=RUST_PSA
```
