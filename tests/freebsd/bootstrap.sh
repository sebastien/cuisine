#!/bin/sh

if [ ! -e /vagrant ]
then
  echo "/vagrant folder missing"
  exit 1
fi

#portsnap fetch

#if [ -e /usr/ports/.portsnap.INDEX ]
#then
    #portsnap update
#else
    #portsnap extract
#fi

#if [ ! -e /usr/local/sbin/portmaster ]
#then
  #cd /usr/ports/ports-mgmt/portmaster
  #export BATCH=yes
  #make rmconfig
  #make install clean
  #echo 'WITH_PKGNG=yes' >> /etc/make.conf
#fi

test -e /usr/local/bin/easy_install || (yes | pkg install sudo python devel/py-setuptools27)
test -e /usr/local/bin/pip || easy_install pip
test -e /usr/local/bin/fabric || pip install fabric
cd /vagrant/
python tests/freebsd/run_cuisine.py
