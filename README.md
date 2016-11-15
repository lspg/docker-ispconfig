ISPConfig is an Open source, BSD-licensed, hosting control panel for Linux, designed to manage Apache, BIND, FTP, and databases, supporting many Linux distributions.

Installation followed official tutorial : https://www.howtoforge.com/tutorial/perfect-server-debian-8-4-jessie-apache-bind-dovecot-ispconfig-3-1/

Mostly inspired by [jerob/docker-ispconfig](https://hub.docker.com/r/jerob/docker-ispconfig/) but with several fixes and improvements.

### **Start ISPConfig**

docker run -name ispconfig  -p 20:20 -p 21:21 -p 30000:30000 -p 30001:30001 -p 30002:30002 -p 30003:30003 -p 30004:30004 -p 30005:30005 -p 30006:30006 -p 30007:30007 -p 30008:30008 -p 30009:30009 -p 80:80 -p 443:443 -p 8080:8080 -p 53:53 -p 2222:22 lspg/ispconfig /usr/local/bin/start.sh

### **Shell access**

docker exec -i -t lspg/ispconfig bash

### **Supervisor status**

http://your-ip:9001
login : root
password : password
To setup authentication : access container shell and edit `/etc/supervisor/supervisord.conf`

### **ISPConfig administration**

https://your-ip:8080
ISPConfig login : admin
ISPConfig password : admin

### **Reconfigure ISPConfig**

`ispconfig_update.sh`

### **Webmail (Rainloop)**

http://your-ip/webmail

### **PHPMyAdmin**

http://your-ip/phpmyadmin

### **MySQL**
root login : root
root password : password
To change root password, access container shell and use following command :
`mysqladmin -u root -p'oldpassword' password newpassword`

It is strongly recommended that you change the MariaDB and ISPConfig password as soon as possible.

### **ROADMAP**
* Code cleaning and refactoring
* Use docker-compose to split project
* Use puppet for software installation
* Follow Dockerfile guidelines
* Include Mails setup into README
* Create Spamassassin & postfix-wrapper supervisor init scripts