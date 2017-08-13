#!/usr/bin/env python2

import sys, argparse, urllib2, re
import pgpy
from blockstack_client.profile import profile_list_accounts

FINGERPRINT_MIN_LEN = 16

parser = argparse.ArgumentParser(description="Fetches and verifies GnuPG keys from Blockstack IDs.")
parser.add_argument("ids", metavar="id", nargs="+", help="Blockstack ID to fetch")
parser.add_argument("--all", dest="printAll", action="store_true", help="print all found keys (default: print only first)")
parser.add_argument("--i-really-want-unverified-keys", dest="dontVerify", action="store_true", help="don't verify keys against the provided fingerprint (default: verify keys)")
parser.add_argument("--disable-fingerprint-length-check", dest="disableLengthCheck", action="store_true", help="Disables security length check for the given fingerprint (default: not active)")
parser.add_argument("-s", "--silent", dest="silent", action="store_true", help="prints nothing except a key / nothing on failure (default: not active)")
parser.add_argument("--debug", dest="debug", action="store_true", help="prints verbose debug information (default: not active)")
parser.set_defaults(printAll=False, dontVerify=False, disableLengthCheck=False)

args = parser.parse_args()



def getKeys(accounts, id):
	keyFound = False

	if not "accounts" in accounts:
		if not args.silent:
			print("Couldn't find valid profile information for \"%s\"" % id)
		if args.debug:
			print("Accounts: %s" % accounts)
		return;

	if args.debug:
		print("%s's accounts: %s" % (id, accounts))

	for account in accounts["accounts"]:
		if account["@type"] == "Account" and account["service"] == "pgp":
			if not args.printAll and not keyFound:
				keyFound = True

				if args.debug:
					print("Identifier: %s" % account["identifier"])
					print("Key URL   : %s" % account["contentUrl"])

				try:
					key = urllib2.urlopen(account["contentUrl"]).read()
				except Exception:
					if not args.silent:
						print("Error while fetching key from \"%s\"" % account["contentUrl"])
					return;

				if args.dontVerify:
					if not args.silent:
						print("PGP key for \"%s\":" % id)
					print(key)
				else:
					if verifyFingerprint(key, account["identifier"]):
						if not args.silent:
							print("PGP key for \"%s\":" % id)
						print(key)
					elif not args.silent:
						print("Couldn't verify fingerprint against key")

	if not keyFound and not args.silent:
		print("No PGP keys found for \"%s\"" % id)

def cleanFingerprint(fingerprint):
	match = re.search("(?:0x)?([0-9a-f]{8,40})", fingerprint, re.IGNORECASE)
	if match:
		cleanedFingerprint = match.group(1)
		cleanedFingerprint = cleanedFingerprint.replace(" ", "")
		cleanedFingerprint = cleanedFingerprint.upper()
	else:
		cleanedFingerprint = None

	if args.debug:
		print("Given fingerprint:  %s" % fingerprint)
		print("Cleaned finerprint: %s" % cleanedFingerprint)

	return cleanedFingerprint


def verifyFingerprint(keyData, expectedFingerprint):
	expectedFinerprint = cleanFingerprint(expectedFingerprint)

	try:
		key, _ = pgpy.PGPKey.from_blob(keyData)
		fingerprint = key.fingerprint
		fingerprint = fingerprint.replace(" ", "")
	except Exception as e:
		if not args.silent:
			print("Error while importing key, probably wasn't able to find a valid key")
		if args.debug:
			print("Exception: %s" % e)
		return False

	if not args.disableLengthCheck and len(expectedFingerprint) < FINGERPRINT_MIN_LEN:
		if not args.silent:
			print("Fingerprint \"%s\" is too short to be secure, fingerprint needs more than %s characters" % (expectedFingerprint, FINGERPRINT_MIN_LEN))
		return False

	if args.debug:
		print("Comparing given fingerprint \"%s\" with calculated fingerprint \"%s\"" % (expectedFingerprint, fingerprint))

	return fingerprint.endswith(expectedFingerprint)



if args.debug:
	print("Names to lookup: %s" % args.ids)

for id in args.ids:
	accounts = profile_list_accounts(id)
	getKeys(accounts, id)
