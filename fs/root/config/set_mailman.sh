#!/bin/bash

# SET TIMEZONE
LOCALE=${1}
sed -i "s|# \(.*${LOCALE}.*\)|\1|" /etc/locale.gen
locale-gen
dpkg-reconfigure locales