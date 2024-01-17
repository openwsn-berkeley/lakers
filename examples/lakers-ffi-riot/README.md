# Using the C Wrapper with RIOT

This example enables using `lakers` alongside the [RIOT operating system](https://github.com/RIOT-OS/RIOT).
See [Requirements](#requirements) below.

# Build and run

First, go to the top level directory and generate the headers and static library:

```bash
# TODO
```

Then, compile and flash to the board (default is nRF52840), as shown below.

With `crypto-cryptocell310`:

```bash
make flash term
```

With `crypto-psa-baremetal`:

```bash
make flash term EDHOC_CRYPTO=CRYPTO_PSA
```

# Requirements

[RIOT](https://github.com/RIOT-OS/RIOT)'s source code must be available in a local folder, which the `Makefile` assumes to be `../../../RIOT`.

If you have RIOT available in another directory, set the `RIOTBASE` variable when invoking `make`.
