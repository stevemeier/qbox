#!/bin/bash

if [ "${TRUSTCLIENT+defined}" ]; then
  echo $$ mail from: $SMTPMAILFROM >&2
  echo $$ rcpt to: $SMTPRCPTTO >&2
  echo N
fi
