Run with `rust-cryptocell310`:

```bash
make all flash term
```

Run with `rust-psa-baremetal`:

```bash
make all flash term EXTRA_CFLAGS+="-D EDHOC_FEATURES=RUST_PSA"
```
