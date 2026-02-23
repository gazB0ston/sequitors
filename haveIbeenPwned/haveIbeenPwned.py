#!/usr/bin/env python3

# 'Have I Been Pwned': inspired by this article:
# https://nakedsecurity.sophos.com/2021/06/02/have-i-been-pwned-breach-site-partners-with-the-fbi/
#
# Main site page: https://haveibeenpwned.com/
#
# The API has lots more capabilities than are currently used in this program.
# Maybe some day ...
# API Docs: https://haveibeenpwned.com/API/v3
#
# This program will send a request to a "known compromised passwords" DB and 
# find if/how-many times the password has been compromised. Ideally the count 
# comes back as 0.
#
# Care is taken to not store or display the password that was input, but 
# there is never any guarantee that it cannot be captured. The user assumes all 
# risk, and is fully responsible to keep their passwords safe and secure.

import os
import sys
import argparse
import hashlib
from getpass import getpass
import requests
import re

def doQuery(hashofQueryPwd, verbose=False):
    # init return empty list
    replyLines = list()

    # capture first 5 characters of hexdigest for request URI
    hash5 = hashofQueryPwd[:5]
    queryURI = f'https://api.pwnedpasswords.com/range/{hash5}'
    if verbose:
        print(f"URI: {queryURI}")

    with requests.Session() as s:
        s.headers.update({'Add-Padding': 'true'})
        s.headers.update({'User-Agent': 'gaz-private-program'})
        r = s.get(queryURI)
        if r.status_code == requests.codes.ok:
            # split response into a list-of-lines
            replyLines = r.text.split("\n")
        else:
            print(f"BAD response status: {r.status_code}")
            # return empty reply

    return replyLines

def checkQuery(hashofQueryPwd, replyLines, verbose=False):
    # last 35 characters of hexdigest
    hash35 = hashofQueryPwd[5:]
    # assume no compromises, adjust as necessary
    nCompromises = 0

    # step through lines finding any case-insensitive matches
    pattern = re.compile(hash35, flags=re.IGNORECASE)
    for line in replyLines:
        result = pattern.match(line)
        # capture the number of compromises known
        if result is not None:
            if verbose:
                print(f"match: {result}")
            nCompromises += int(line.split(":")[1])
            # there will be only one match so from here we're done
            break

    return nCompromises

def getPasswdHash():
    # read password from stdin, do not echo or store it
    # get SHA1 hexdigest of password
    return hashlib.sha1(getpass(prompt="Enter password to be checked: ").encode()).hexdigest()

def main():
    # init things
    rc = 0

    parser = argparse.ArgumentParser(
            description="read a password from STDIN with no echo and check if it has known compromises")
    parser.add_argument(
            '--verbose',
            action='store_true',
            default=False,
            help="show more information")
    args = parser.parse_args()

    if len(sys.argv) > 1:
        if 'verbose' in sys.argv:
            verbose = 1

    # get SHA1 hexdigest of password
    hashofQueryPwd = getPasswdHash()
    if args.verbose:
        print(f"Hash of password: {hashofQueryPwd.upper()}")
    # send request
    replyLines = doQuery(hashofQueryPwd, verbose=args.verbose)
    if len(replyLines) == 0:
        print("No response received for your password query")
    else:
        if args.verbose:
            print(f"response contains {len(replyLines)} lines")

        # find how many compromises are known
        nCompromises = checkQuery(hashofQueryPwd, replyLines, verbose=args.verbose)
        print(f"### your password has {nCompromises} compromises")

    return rc

if __name__ == "__main__":
    sys.exit(main())
