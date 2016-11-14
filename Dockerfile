#
#                    ##        .            
#              ## ## ##       ==            
#           ## ## ## ##      ===            
#       /""""""""""""""""\___/ ===        
#  ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~   
#       \______ o          __/            
#         \    \        __/             
#          \____\______/                
# 
#          |          |
#       __ |  __   __ | _  __   _
#      /  \| /  \ /   |/  / _\ | 
#      \__/| \__/ \__ |\_ \__  |
#
# Dockerfile for ISPConfig 3
#
# https://www.howtoforge.com/tutorial/perfect-server-debian-8-4-jessie-apache-bind-dovecot-ispconfig-3-1
#

FROM debian:jessie

MAINTAINER Loïs PUIG <lois.puig@kctus.fr> version: 0.1

# Let the container know that there is no tty
ENV DEBIAN_FRONTEND="noninteractive"

ARG	FQDN="ispconfig.docker"
ARG	LOCALE="en_US"
ARG	TIMEZONE="UTC"
ARG	MYSQL_ROOT_PWD="password"
ARG	PHPMYADMIN_PWD="password"
ARG	MAILMAN_EMAIL=""
ARG	MAILMAN_PWD="password"
ARG	SSLCERT_ORGANIZATION="My Organization"
ARG	SSLCERT_UNITNAME="Docked Services"
ARG	SSLCERT_EMAIL="root@ispconfig.docker"
ARG	SSLCERT_LOCALITY="New York"
ARG	SSLCERT_STATE="New York"
ARG	SSLCERT_COUNTRY="US"
ARG	SUPERVISOR_LOGIN="root"
ARG	SUPERVISOR_PWD="password"

ADD ./fs /

	# --- 0.1 Update Your Debian Installation
RUN apt-get -y -qq update && \
	apt-get -y -qq install apt-utils screenfetch && \
	apt-get -y -qq upgrade

	# --- 0.2 Bash
RUN echo '. ~/.bash_aliases' >> /root/.bashrc && \
	echo "export TERM=xterm" >> /root/.bashrc && \
	# --- 0.3 locales
	apt-get update && apt-get -y -qq upgrade && apt-get install -y locales && rm -rf /var/lib/apt/lists/* && \
    localedef -i ${LOCALE} -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG ${LOCALE}.utf8

	# --- 0.2 Supervisor
RUN apt-get update && \
	apt-get -y -qq install rsyslog rsyslog-relp logrotate wget curl python-pip && \
	pip install supervisor && \
	sed -i "s/{{ SUPERVISOR_LOGIN }}/${SUPERVISOR_LOGIN}/g" /etc/supervisor/supervisord.conf && \
	sed -i "s/{{ SUPERVISOR_PWD }}/${SUPERVISOR_PWD}/g" /etc/supervisor/supervisord.conf && \
	chmod 755 /usr/local/bin/* && \
	mkdir -p /var/run/sshd /var/log/supervisor /var/run/supervisor && \
	mv /bin/systemctl /bin/systemctloriginal

	# --- 1 Preliminary
RUN echo "${TIMEZONE}" > /etc/timezone && \
	dpkg-reconfigure tzdata && \
	# Create the log file to be able to run tail
	touch /var/log/cron.log /var/log/auth.log

	# --- 2 Install the SSH server
RUN apt-get -qq update && \
	apt-get -y -qq install ssh openssh-server rsync && \
	# --- 3 Install a shell text editor
	apt-get -y -qq install nano vim-nox && \
	# --- 6 Change The Default Shell
	echo "dash  dash/sh boolean no" | debconf-set-selections && \
	dpkg-reconfigure dash && \
	# --- 7 Synchronize the System Clock
	apt-get -y -qq install ntp ntpdate

	# --- 8 Install Postfix, Dovecot, MySQL, phpMyAdmin, rkhunter, binutils
RUN echo "mariadb-server  mariadb-server/root_password_again password ${MYSQL_ROOT_PWD}" | debconf-set-selections && \
	echo "mariadb-server  mariadb-server/root_password password ${MYSQL_ROOT_PWD}" | debconf-set-selections && \
	echo "mariadb-server-10.0 mysql-server/root_password password ${MYSQL_ROOT_PWD}" | debconf-set-selections && \
	echo "mariadb-server-10.0 mysql-server/root_password_again password ${MYSQL_ROOT_PWD}" | debconf-set-selections && \
	apt-get -qq update && \
	apt-get -qq -y --force-yes install postfix postfix-mysql postfix-doc mariadb-client mariadb-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-sieve dovecot-lmtpd sudo && \
	sed -i 's/^bind-address/#bind-address/g' /etc/mysql/my.cnf && \
	mkdir -p /var/backups/sql && \
	service postfix restart && \
	service mysql restart

	# --- 9 Install Amavisd-new, SpamAssassin And Clamav
RUN apt-get -qq update && \
	apt-get -y -qq install amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl postgrey && \
	chown root:clamav /etc/clamav/clamd.conf && \
	chmod g+r /etc/clamav/clamd.conf && \
	mkdir -p /var/mail/postgrey && \
	chown -R postgrey:postgrey /var/mail/postgrey && \
	chmod 700 /var/mail/postgrey && \
	mkdir -p /var/run/clamav && \
	chown -R clamav: /var/run/clamav && \
	service spamassassin stop && \
	systemctl disable spamassassin &>/dev/null && \
	freshclam

	# --- 9.1 Install Metronome XMPP Server
RUN echo "deb http://packages.prosody.im/debian jessie main" > /etc/apt/sources.list.d/metronome.list && \
	wget http://prosody.im/files/prosody-debian-packages.key -O - | apt-key add - && \
	apt-get -qq update && \
	apt-get -y -qq install git lua5.1 liblua5.1-0-dev lua-filesystem libidn11-dev libssl-dev lua-zlib lua-expat lua-event lua-bitop lua-socket lua-sec luarocks luarocks && \
	luarocks install lpc && \
	adduser --no-create-home --disabled-login --gecos 'Metronome' metronome && \
	cd /opt && \
	git clone https://github.com/maranda/metronome.git metronome && \
	cd /opt/metronome && \
	./configure --ostype=debian --prefix=/usr && \
	make && \
	make install

	# --- 10 Install Apache2, PHP5, phpMyAdmin, FCGI, suExec, Pear, And mcrypt
RUN echo 'phpmyadmin phpmyadmin/dbconfig-install boolean true' | debconf-set-selections && \
	echo 'phpmyadmin phpmyadmin/mysql/admin-pass password pass' | debconf-set-selections && \
	echo 'phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2' | debconf-set-selections && \
	service mysql restart && \
	echo $(grep $(hostname) /etc/hosts | cut -f1) ${FQDN} >> /etc/hosts && \
	apt-get -qq update && \
	apt-get -y -qq install apache2 apache2.2-common apache2-doc apache2-mpm-prefork apache2-utils libexpat1 ssl-cert libapache2-mod-php5 php5 php5-common php5-gd php5-mysql php5-imap phpmyadmin php5-cli php5-cgi libapache2-mod-fcgid apache2-suexec php-pear php-auth php5-mcrypt mcrypt php5-imagick imagemagick libruby libapache2-mod-python php5-curl php5-intl php5-memcache php5-memcached php5-pspell php5-recode php5-sqlite php5-tidy php5-xmlrpc php5-xsl memcached libapache2-mod-passenger && \
	echo "ServerName ${FQDN}" > /etc/apache2/conf-available/servername.conf && \
	a2enconf servername && \
	a2enmod suexec rewrite ssl actions include dav_fs dav auth_digest cgi headers && \
	a2enconf httpoxy && \
	a2dissite 000-default && \
	service apache2 restart

	# --- 10.1 Install HHVM (HipHop Virtual Machine)
RUN apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0x5a16e7281be7a449 && \
	echo deb http://dl.hhvm.com/debian jessie main | tee /etc/apt/sources.list.d/hhvm.list && \
	apt-get -qq update && \
	apt-get -y -qq install hhvm

	# --- 11 Install Let's Encrypt client (certbot)
RUN apt-get -qq update && \
	apt-get -y install python-certbot-apache -t jessie-backports

	# --- 12.1 PHP-FPM
RUN apt-get -qq update && \
	apt-get -y -qq install libapache2-mod-fastcgi php5-fpm && \
	a2enmod actions fastcgi alias && \
	service apache2 restart

	# --- 12.2 Install XCache
RUN apt-get -qq update && \
	apt-get -y -qq install php5-xcache && \
	service apache2 restart

	# --- 13 Install Mailman
RUN /bin/bash -c 'echo "mailman	mailman/default_server_language	select	${LOCALE:0:2}" | debconf-set-selections' && \
	/bin/bash -c 'echo "mailman	mailman/site_languages	multiselect	${LOCALE:0:2}" | debconf-set-selections' && \
	apt-get -qq update && \
	apt-get -y -qq install mailman && \
	newaliases && \
	service postfix restart && \
	ln -s /etc/mailman/apache.conf /etc/apache2/conf-available/mailman.conf && \
	a2enconf mailman

	# --- 14 Install PureFTPd And Quota
RUN apt-get -qq update && \
	apt-get -qq -y --force-yes install dpkg-dev debhelper openbsd-inetd debian-keyring && \
	apt-get -y -qq build-dep pure-ftpd && \
	mkdir /tmp/pure-ftpd-mysql/ && \
    cd /tmp/pure-ftpd-mysql/ && \
    apt-get -qq source pure-ftpd-mysql && \
    cd pure-ftpd-* && \
    sed -i '/^optflags=/ s/$/ --without-capabilities/g' ./debian/rules && \
    dpkg-buildpackage -b -uc > /tmp/pureftpd-build-stdout.txt 2> /tmp/pureftpd-build-stderr.txt && \
	dpkg -i /tmp/pure-ftpd-mysql/pure-ftpd-common*.deb && dpkg -i /tmp/pure-ftpd-mysql/pure-ftpd-mysql*.deb && \
	# Prevent pure-ftpd upgrading
	apt-mark hold pure-ftpd-common pure-ftpd-mysql && \
	# setup ftpgroup and ftpuser
	groupadd ftpgroup && \
	useradd -g ftpgroup -d /dev/null -s /etc ftpuser && \
	apt-get -y -qq install quota quotatool && \
	echo 1 > /etc/pure-ftpd/conf/TLS && \
	mkdir -p /etc/ssl/private/ && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_ORGANIZATION }}/${SSLCERT_ORGANIZATION}/g" /root/config/openssl.cnf' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_UNITNAME }}/${SSLCERT_UNITNAME}/g" /root/config/openssl.cnf' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_EMAIL }}/${SSLCERT_EMAIL}/g" /root/config/openssl.cnf' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_LOCALITY }}/${SSLCERT_LOCALITY}/g" /root/config/openssl.cnf' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_STATE }}/${SSLCERT_STATE}/g" /root/config/openssl.cnf' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_COUNTRY }}/${SSLCERT_COUNTRY}/g" /root/config/openssl.cnf' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_CN }}/${FQDN}/g" /root/config/openssl.cnf' && \
	openssl req -x509 -nodes -days 7300 -newkey rsa:4096 -config /root/config/openssl.cnf -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem && \
	chmod 600 /etc/ssl/private/pure-ftpd.pem && \
	service pure-ftpd-mysql restart

	# --- 15 Install BIND DNS Server
RUN apt-get -qq update && \
	apt-get -y -qq install bind9 dnsutils && \
	# --- 16 Install Vlogger, Webalizer, And AWStats
	apt-get -y -qq install vlogger webalizer awstats geoip-database libclass-dbi-mysql-perl && \
	# --- 17 Install Jailkit
	apt-get -y -qq install build-essential autoconf automake libtool flex bison debhelper binutils && \
	cd /tmp && \
	wget -nv http://olivier.sessink.nl/jailkit/jailkit-2.19.tar.gz && \
	tar xvfz jailkit-2.19.tar.gz && \
	cd jailkit-2.19 && \
	./debian/rules binary && \
	cd /tmp && \
	dpkg -i jailkit_2.19-1_*.deb && \
	rm -rf jailkit*

	# --- 18 Install fail2ban and UFW Firewall
RUN apt-get -qq update && \
	apt-get -y -qq install fail2ban && \
	echo "ignoreregex =" >> /etc/fail2ban/filter.d/postfix-sasl.conf && \
	touch /var/log/mail.log /var/log/syslog && \
	chmod 644 /var/log/mail.log && \
	service fail2ban restart && \
	apt-get -y -qq install ufw

	# --- 19 Install Rainloop
RUN mkdir -p /usr/share/rainloop && cd /usr/share/rainloop && \
	curl -s http://repository.rainloop.net/installer.php | php && \
	chmod 644 /etc/apache2/conf-available/rainloop.conf && \
	a2enconf rainloop && \
	chown -R www-data: /usr/share/rainloop && \
	find /usr/share/rainloop/ -type d -exec chmod 0755 {} \; && \
	find /usr/share/rainloop/ -type f -exec chmod 0644 {} \;

	# --- 20 Prepare ISPConfig install
RUN cd /tmp && \
	wget -nv http://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz && \
	tar xfz ISPConfig-3-stable.tar.gz && \
	rm ISPConfig-3-stable.tar.gz && \
	/bin/bash -c 'sed -i "s/{{ LANG }}/${LOCALE:0:2}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ FQDN }}/${FQDN}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ MYSQL_ROOT_PWD }}/${MYSQL_ROOT_PWD}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_ORGANIZATION }}/${SSLCERT_ORGANIZATION}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_UNITNAME }}/${SSLCERT_UNITNAME}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_EMAIL }}/${SSLCERT_EMAIL}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_LOCALITY }}/${SSLCERT_LOCALITY}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_STATE }}/${SSLCERT_STATE}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_COUNTRY }}/${SSLCERT_COUNTRY}/g" /root/config/ispconfig-autoinstall.ini' && \
	/bin/bash -c 'sed -i "s/{{ SSLCERT_CN }}/${SSLCERT_CN}/g" /root/config/ispconfig-autoinstall.ini' && \
	# Install ISPConfig
	cp /root/config/ispconfig-autoinstall.ini /tmp/ispconfig3_install/install/autoinstall.ini && \
	service mysql restart && \
	php -q /tmp/ispconfig3_install/install/install.php --autoinstall=/tmp/ispconfig3_install/install/autoinstall.ini && \
	sed -i 's/^NameVirtualHost/#NameVirtualHost/g' /etc/apache2/sites-enabled/000-ispconfig.vhost && \
	sed -i 's/^NameVirtualHost/#NameVirtualHost/g' /etc/apache2/sites-enabled/000-ispconfig.conf

	# CLEANING
RUN apt-get autoremove -y && apt-get clean && rm -rf /tmp/*

EXPOSE 20/tcp 21/tcp 22/tcp 53 80/tcp 443/tcp 953/tcp 8080/tcp 3306 9001/tcp

VOLUME ["/var/www/","/var/mail/","/var/backups/","/var/lib/mysql","/etc/","/usr/local/ispconfig","/var/log/"]

CMD ["/bin/bash", "/usr/local/bin/startup"]