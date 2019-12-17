#!/bin/sh

# Build requirements
yum -y install git
yum -y install epel-release
yum -y install golang
yum -y install libuuid-devel

# Database
yum -y install mariadb-server mariadb
service mariadb start

# Antispam / Antivir
yum -y install spamassassin clamav

mkdir /etc/qbox
echo -n root > /etc/qbox/dbuser
echo -n > /etc/qbox/dbpass

mkdir -p /home/mail/testuser1
mkdir -p /home/mail/testuser2
mkdir -p /home/mail/testuser3
mkdir -p /home/mail/testuser4
chown -R mail:mail /home/mail

echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser1","testpass1","/home/mail/testuser1",0,0);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser2","testpass2","/home/mail/testuser2",1,0);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser3","testpass3","/home/mail/testuser3",0,1);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser4","testpass4","/home/mail/testuser4",1,1);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser5","testpass5","|/usr/bin/false");' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser6","testpass6","|/usr/bin/true");' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser7","testpass7","root@localhost");' | mysql

echo 'INSERT INTO qbox.mapping VALUES ("nofilter","localhost",1,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("antispam","localhost",2,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("antivir","localhost",3,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("spamvir","localhost",4,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("false","localhost",5,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("true","localhost",6,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("forward","localhost",7,"");' | mysql