#!/bin/bash

# RUN mysqladmin -u root password pass
OLDPWD=${1}
NEWPWD=${2}

: "${MAILMAN_EMAIL:?Need to set environment variable MAILMAN_EMAIL to non-empty value}"
: "${MAILMAN_PWD:?Need to set environment variable MAILMAN_PWD to non-empty value}"

mysqladmin -u root -p'password' password newpass