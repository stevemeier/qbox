#!/bin/bash

# No Filter Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=nofilter@localhost /opt/qbox/deliver < ${I}; done
find /home/mail/testuser1 -type f | wc -l

# Antispam Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=antispam@localhost /opt/qbox/deliver < ${I}; done
grep -h ^X-Spam-Checker-Version /home/mail/testuser2/INBOX/new/* | sort | uniq -c

# Antivir Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=antivir@localhost /opt/qbox/deliver < ${I}; done
find /home/mail/testuser3 -type f | wc -l

# Antispam + Antivir Tests
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=spamvir@localhost /opt/qbox/deliver < ${I}; done
find /home/mail/testuser4 -type f | wc -l

# Pipe to `false`
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=false@localhost /opt/qbox/deliver < ${I}; echo $?; done

# Pipe to `true`
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=true@localhost /opt/qbox/deliver < ${I}; echo $?; done
