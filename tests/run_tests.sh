#!/bin/bash

# No Filter Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=nofilter@localhost /opt/qbox/deliver < ${I}; done

# Antispam Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=antispam@localhost /opt/qbox/deliver < ${I}; done
grep -h ^X-Spam-Checker-Version /home/mail/testuser2/INBOX/new/* | uniq -c

# Antivir Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=antivir@localhost /opt/qbox/deliver < ${I}; done
