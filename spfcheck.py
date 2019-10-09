#!/usr/bin/python2

import os
import spf
import sys

# RELAYCLIENTs and TRUSTCLIENTs can pass
if "RELAYCLIENT" in os.environ or "TRUSTCLIENT" in os.environ:
  print
  exit()

# Get the client's IP from %ENV
remoteip = ""
if os.environ.get('TCPREMOTEIP'):
  remoteip = os.environ['TCPREMOTEIP']
if os.environ.get('TCP6REMOTEIP'):
  remoteip = os.environ['TCP6REMOTEIP']
if os.environ.get('SSLREMOTEIP'):
  remoteip = os.environ['SSLREMOTEIP']

# Exit if we can not get client IP
if len(remoteip) == 0:
  print
  exit()

# Exit if the host did not say hel(l)o
if not os.environ.get('SMTPHELOHOST'):
  print
  exit()

# Exit if there is no sender
if not os.environ.get('SMTPMAILFROM'):
  print
  exit()

# Run the SPF check
result, explanation = spf.check2(i=remoteip, s=os.environ['SMTPMAILFROM'], h=os.environ['SMTPHELOHOST'])

# Only fails will be rejected
if result == "fail":
  print >> sys.stderr, "%d SPF check failed for %s" % (os.getppid(), os.environ['SMTPMAILFROM'])
  print "E451 SPF check failed [%s]" % explanation
else:
  print

exit()
