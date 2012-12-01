#!/usr/bin/env python2

from hashlib import sha1

cnt = 0
last = None
curr = sha1('')

print 'cnt=%d last=%s curr=%s' % (
    cnt, last, curr.hexdigest())

while last != curr:
    cnt += 1
    if (cnt & 0xffffffff) == 0:
        print 'cnt=%d last=%s curr=%s' % (
            cnt, last.hexdigest(), curr.hexdigest())
    last = curr
    curr = sha1(curr.digest())

print 'holy shit!'
print 'cnt=%d last=%s curr=%s' % (
    cnt, last.hexdigest(), curr.hexdigest())
