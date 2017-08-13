# blockstack-gpg

## Installation

Clone this repository
```bash
$ git clone https://github.com/ntzwrk/blockstack-gpg
$ cd blockstack-gpg
```
Then run the setup script
```bash
$ ./setup.py install --user
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
$ ./blockstack_gpg/main.py muneeb.id | gpg
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
pub   rsa4096/0x639C89272AFEC540 2014-03-28 [SC]
      Key fingerprint = 9862 A3FB 338B E9EB 6C6A  5E05 639C 8927 2AFE C540
uid                             Muneeb Ali (See http://muneebali.com) <muneeb@ali.vc>
sub   rsa4096/0x0C1F397D12E6F05D 2014-03-28 [E]
```

Or import the key directly:
```bash
$ ./blockstack_gpg/main.py muneeb.id | gpg --import
gpg: key 0x639C89272AFEC540: public key "Muneeb Ali (See http://muneebali.com) <muneeb@ali.vc>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

## License

This code is published under the [GNU General Public License v3.0](LICENSE.md).
