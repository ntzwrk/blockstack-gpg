# blockstack-gpg

## Installation

Clone this repository
```bash
$ git clone https://github.com/ntzwrk/blockstack-gpg
$ cd blockstack-gpg
```
Then run the setup script
```bash
$ ./setup.py install
```
And install a custom version of the GnuPG library (as the other one is broken)
```bash
$ pip install https://github.com/SexualHealthInnovations/python-gnupg/tarball/issue157#egg=gnupg
```

## Usage

```bash
usage: main.py [-h] [--all] [--i-really-want-unverified-keys] [-s] [--debug]
               id [id ...]

Fetches and verifies GnuPG keys from Blockstack IDs.

positional arguments:
  id                    Blockstack ID to fetch

optional arguments:
  -h, --help            show this help message and exit
  --all                 print all found keys (default: print only first)
  --i-really-want-unverified-keys
                        don't verify keys against the provided fingerprint
                        (default: verify keys)
  -s, --silent          prints nothing except a key / nothing on failure
                        (default: not active)
  --debug               prints verbose debug information (default: not active)
```

You can pipe the output directly into GPG:
```bash
$ ./blockstack_gpg/main.py ryan.id | gpg
```

## License

This code is published under the [GNU General Public License v3.0](LICENSE.md).
