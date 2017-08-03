#!/usr/bin/env python2

from setuptools import setup, find_packages

exec(open("blockstack_gpg/version.py").read())

setup(
	name="blockstack-gpg",
	version=__version__,
	url="https://github.com/ntzwrk/blockstack-gpg",
	license="GPLv3",
	author="ntzwrk",
	author_email="contact@ntzwrk.org",
	description="Download and verify GPG keys from blockstack",
	packages=find_packages(),
	dependency_links = ['https://github.com/SexualHealthInnovations/python-gnupg/tarball/issue157#egg=gnupg-unknown'],
	install_requires=[
		"blockstack>=0.14.3",
		"gnupg==unknown"
	],
)
