# Using the C Wrapper with RIOT

This example enables using `lakers` alongside the [RIOT operating system](https://github.com/RIOT-OS/RIOT).
It uses ARM's Crypto Cell as crypto backend.
See [Requirements](#requirements) below.

# Build and run

First, go to the top level directory and generate the headers and static library:

```bash
./build_for_c.sh crypto-cryptocell310
```

Then, compile and flash to the board (default is nRF52840), as shown below.

```bash
make flash term
```

# Requirements

[RIOT](https://github.com/RIOT-OS/RIOT)'s source code must be available in a local folder, which the `Makefile` assumes to be `../../../RIOT`.

If you have RIOT available in another directory, set the `RIOTBASE` variable when invoking `make`.
