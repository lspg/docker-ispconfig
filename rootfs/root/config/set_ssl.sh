#!/bin/bash

if [ -f "/root/config/openssl.cnf" ]; then
	# Pure-FTP
	openssl req -x509 -nodes -days 7300 -newkey rsa:4096 -config /root/config/openssl.cnf -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
	chmod 600 /etc/ssl/private/pure-ftpd.pem
	service pure-ftpd-mysql restart

	# ISPConfig web GUI
	cp -p /etc/ssl/private/pure-ftpd.pem /usr/local/ispconfig/interface/ssl/ispserver.crt
	cp -p /etc/ssl/private/pure-ftpd.pem /usr/local/ispconfig/interface/ssl/ispserver.key
	service apache2 restart
fi