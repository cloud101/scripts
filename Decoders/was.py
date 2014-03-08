#!/usr/bin/env python
import sys
from operator import xor
try:
    s = sys.argv[1]
    decoded = s.decode('base64','strict')
    xorWord = lambda ss,cc: ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,cc*100))
    decrypt = xorWord(decoded,'_')
    print decrypt
except:
    print "Did you give  a correct WAS password?"

