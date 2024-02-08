# Lakers Python
Python wrapper for the [`lakers` crate](https://github.com/openwsn-berkeley/lakers).

# Installation and usage

```console
pip install lakers-python
```

```python
import lakers

# generate a keypair
lakers.p256_generate_key_pair()

# instantiate a initiator and prepare EDHOC's message 1
initiator = lakers.EdhocInitiator()
message_1 = initiator.prepare_message_1(c_i=None, ead_1=None)

# for more examples, see the tests in the repository
```

# Development

To build and test:
```bash
maturin develop
pytest
```

## Requirements

The maturin executable must be available. The recommended way is to install and use it in a virtual environment:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip maturin pytest
pip freeze
```
