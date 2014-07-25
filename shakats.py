#!/usr/bin/env python
"""Python script to generate systematic KATs for Closure's SHA tests"""
from __future__ import division, print_function

from binascii import hexlify
from hashlib import sha1, sha224, sha256, sha384, sha512

from Crypto.Cipher import AES

C = AES.new('Closure Library SHA KATs        ')

TEST_HEADER = '''\
goog.provide('goog.crypt.ShaKatsTest');
goog.setTestOnly('goog.crypt.ShaKatsTest');

goog.require('goog.array');
goog.require('goog.crypt');
goog.require('goog.crypt.Sha1');
goog.require('goog.crypt.Sha224');
goog.require('goog.crypt.Sha256');
goog.require('goog.crypt.Sha384');
goog.require('goog.crypt.Sha512');
goog.require('goog.testing.jsunit');

'''

def katbytes(katlen):
    """Generate a pseudorandom message to digest."""
    n = (katlen + 15) // 16
    s = ''
    for x in range(n):
      block = 'KAT {katlen:04}B: {x:02}/{n:02}'.format(katlen=katlen, x=x, n=n)
      s += C.encrypt(block)
    return s[:katlen]


TEST1_TEMPLATE = '''\
  // {shaname} length {len}
  sha.reset();
  sha.update(goog.crypt.hexToByteArray('{prompt}'));
  assertEquals('{kat}',
               goog.crypt.byteArrayToHex(sha.digest()));
'''
SHAS = [[sha1, sha224, sha256, sha384, sha512],
        ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']]

FUNC_TEMPLATE = '''\
function testKats{shatitle}() {{
  var sha = new goog.crypt.{shatitle}();
  {tests}
}}

'''

def gen_test1():
  for sha, shaname in zip(*SHAS):
    body = []
    for katlen in range(1585):
      prompt = katbytes(katlen)
      answer = sha(prompt).digest()
      t = TEST1_TEMPLATE.format(prompt=hexlify(prompt), len=katlen,
                                shaname=shaname, kat=hexlify(answer))
      body += [t]
    print(FUNC_TEMPLATE.format(shatitle=shaname.title(), tests='\n'.join(body)))

if __name__ == '__main__':
  print(TEST_HEADER)
  gen_test1()
