#!/bin/bash

# SET HOSTNAME
#if [ ${FQDN} ] && [ ! ${FQDN} == $(/bin/hostname -f) ]; then
if [ ! -z "${FQDN}" ] && [ ! ${FQDN} == "ispconfig.docker" ]; then
	echo $(grep $(hostname) /etc/hosts | cut -f1) ${FQDN}
#	echo ${FQDN} > /etc/hostname
#	/bin/hostname -F /etc/hostname
fi