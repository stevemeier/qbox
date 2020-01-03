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
freshclam
service spamassassin start

# Install qmail
yum -y install http://repo.openfusion.net/centos7-x86_64/openfusion-release-0.7-1.of.el7.noarch.rpm
yum -y install qmail
yum -y install screen
/usr/bin/screen -d -m /var/qmail/rc

# Clone and build code
cd /opt
git clone https://github.com/stevemeier/qbox.git
cd qbox
make

# Prepare config
mkdir /etc/qbox
echo -n root > /etc/qbox/dbuser
echo -n > /etc/qbox/dbpass

# Prepare filesystem
mkdir -p /home/mail/testuser1/INBOX/new /home/mail/testuser1/INBOX/tmp /home/mail/testuser1/INBOX/cur
mkdir -p /home/mail/testuser2/INBOX/new /home/mail/testuser2/INBOX/tmp /home/mail/testuser2/INBOX/cur
mkdir -p /home/mail/testuser3/INBOX/new /home/mail/testuser3/INBOX/tmp /home/mail/testuser3/INBOX/cur
mkdir -p /home/mail/testuser4/INBOX/new /home/mail/testuser4/INBOX/tmp /home/mail/testuser4/INBOX/cur
mkdir -p /home/mail/testuser9/INBOX/new /home/mail/testuser9/INBOX/tmp /home/mail/testuser9/INBOX/cur
chown -R mail:mail /home/mail

# Load SQL schema
mysql < /opt/qbox/sql/qbox.sql

# Put test data into SQL
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser1","testpass1","/home/mail/testuser1",0,0);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser2","testpass2","/home/mail/testuser2",1,0);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser3","testpass3","/home/mail/testuser3",0,1);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, antispam, antivir) VALUES ("testuser4","testpass4","/home/mail/testuser4",1,1);' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser5","testpass5","|/usr/bin/false");' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser6","testpass6","|/usr/bin/true");' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser7","testpass7","root@localhost");' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir) VALUES ("testuser8","testpass8","/dev/null");' | mysql
echo 'INSERT INTO qbox.passwd (username, password, homedir, dupfilter) VALUES ("testuser9","testpass9","/home/mail/testuser9",1);' | mysql

echo 'INSERT INTO qbox.mapping VALUES ("nofilter","localhost",1,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("antispam","localhost",2,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("antivir","localhost",3,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("spamvir","localhost",4,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("false","localhost",5,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("true","localhost",6,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("forward","localhost",7,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("truefalse","localhost",5,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("truefalse","localhost",6,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("testusers","localhost",1,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("testusers","localhost",2,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("testusers","localhost",3,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("testusers","localhost",4,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("devnull","localhost",8,"");' | mysql
echo 'INSERT INTO qbox.mapping VALUES ("dupfilter","localhost",9,"");' | mysql

# Extract test data
cd /opt/qbox/tests
tar xzf emails.tgz
