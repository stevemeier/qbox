#!/bin/bash

# No Filter Tests
echo '*** START: NO FILTER ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=nofilter@localhost /opt/qbox/deliver < ${I}; done
find /home/mail/testuser1 -type f | wc -l
echo '*** END: NO FILTER ***'
echo

# Antispam Tests
echo '*** START: ANTISPAM ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=antispam@localhost /opt/qbox/deliver < ${I}; done
grep -h ^X-Spam-Checker-Version /home/mail/testuser2/INBOX/new/* | sort | uniq -c
echo '*** END: ANTISPAM ***'
echo

# Antivir Tests
echo '*** START: ANTIVIR ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=antivir@localhost /opt/qbox/deliver < ${I}; done
find /home/mail/testuser3 -type f | wc -l
echo '*** END: ANTIVIR ***'
echo

# Antispam + Antivir Tests
echo '*** START: ANTISPAM + ANTIVIR ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=spamvir@localhost /opt/qbox/deliver < ${I}; done
find /home/mail/testuser4 -type f | wc -l
echo '*** END: ANTISPAM + ANTIVIR ***'
echo

# Pipe to `false`
echo '*** START: PIPE FALSE ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=false@localhost /opt/qbox/deliver < ${I}; echo $?; done
echo '*** END: PIPE FALSE ***'
echo

# Pipe to `true`
echo '*** START: PIPE TRUE ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=true@localhost /opt/qbox/deliver < ${I}; echo $?; done
echo '*** END: PIPE TRUE ***'
echo

# Pipe to `true` and `false`
echo '*** START: PIPE TRUE+FALSE ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=truefalse@localhost /opt/qbox/deliver < ${I}; echo $?; done
echo '*** END: PIPE TRUE+FALSE ***'
echo

# Test dupfilter
echo '*** START: DUPFILTER ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=dupfilter@localhost /opt/qbox/deliver < ${I}; echo $?; done
find /home/mail/testuser9 -type f | wc -l
echo '*** END: DUPFILTER ***'
echo

# Test /dev/null
echo '*** START: DEV/NULL ***'
for I in `find /opt/qbox/tests/emails -name '*.eml' -type f`; do RECIPIENT=devnull@localhost /opt/qbox/deliver < ${I}; echo $?; done
echo '*** END: DEV/NULL ***'
echo
