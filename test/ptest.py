#!/usr/bin/env python

import re
import pexpect

p = pexpect.spawn('./test.sh', timeout=1)
p.expect('rkscli: ')
print "> set encryption wlan8"
p.sendline('set encryption wlan8')
p.expect('Wireless\sEncryption\sType:\s$')
print "> 3"
p.sendline('3')

p.expect('VALUE: (.*)\r\n')

print p.match.group(1)
