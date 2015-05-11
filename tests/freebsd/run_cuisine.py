# -*- coding: utf-8 -*-
# EOF - vim: ts=4 sw=4 expandtab

import imp

cuisine = imp.load_source('cuisine', 'src/cuisine.py')

cuisine.mode_local()

cuisine.log_message('Select BSD options')
cuisine.select_os_flavour("bsd")

cuisine.python_package_ensure("epdb")


cuisine.log_message('check and install pkng')
cuisine.select_package("pkgng")

cuisine.log_message('do system upgrade')
cuisine.package_upgrade()

cuisine.log_message('check and install bash')
cuisine.package_ensure("bash")

cuisine.log_message('check and create group users with gid 100')

cuisine.group_ensure('users', gid=100)

cuisine.log_message('check and create user azul, password is "password"')
cuisine.user_ensure('azul',
                        passwd='$1$q3jGxcnx$RFL8DmJkNli8C2yv0viVE/',
                        home='/home/azul',
                        gid=100,
                        uid=15626,
                        shell='/usr/local/bin/bash')



# Xwindows
cuisine.log_message('check and install xorg')
cuisine.package_ensure("xorg")

cuisine.log_message('create new X11 config if needed')
cuisine.run('(test -e /etc/X11/xorg.conf || Xorg -configure) || true')

cuisine.log_message('check and install xorg')
cuisine.run('( test -e /root/xorg.conf.new && ' +
            'mv /root/xorg.conf.new /etc/X11/xorg.conf) || true')

# XFCE
cuisine.log_message('check and install xfce')
cuisine.package_ensure("xfce")

# Slim
cuisine.log_message('check and install slim')
cuisine.package_ensure("slim")

cuisine.log_message('check and update rc.conf for slim')
rc_conf = cuisine.text_ensure_line(cuisine.file_read(
    '/etc/rc.conf'),
    'slim_enable="YES"',
    'hald_enable="YES"',
    'dbus_enable="YES"')
cuisine.file_write('/etc/rc.conf', rc_conf)
cuisine.run('service hald status || service hald start')
cuisine.run('service dbus status || service dbus start')
cuisine.run('service slim status || service slim start')

# VirtualBox
cuisine.log_message('check and install virtualbox')
cuisine.package_ensure("virtualbox-ose")

cuisine.log_message('check and update fstab for virtualbox')
fstab = cuisine.text_ensure_line(cuisine.file_read('/etc/fstab'),
                                 'fdesc   ' +
                                 '/dev/fd ' +
                                 'fdescfs ' +
                                 'rw      ' +
                                 '0       ' +
                                 '0       ')
cuisine.file_write('/etc/fstab', fstab)

cuisine.log_message('check and update rc.conf for virtualbox')
rc_conf = cuisine.text_ensure_line(cuisine.file_read(
    '/etc/rc.conf'),
    'vboxguest_enable="YES"',
    'vboxnet_enable="YES"',
    'vboxservice_enable="YES"')
cuisine.file_write('/etc/rc.conf', rc_conf)

cuisine.run('kldload vboxdrv >/dev/null 2>&1|| true ')

cuisine.log_message('check and update loader.conf for virtualbox')
loader_conf = cuisine.text_ensure_line(cuisine.file_read(
    '/boot/loader.conf'),
    'vboxdrv_load="YES"')
cuisine.file_write('/boot/loader.conf', loader_conf)

cuisine.log_message('check that azul is part of vboxusers')
cuisine.group_user_ensure_bsd('vboxusers', 'azul')
cuisine.group_user_ensure_bsd('operator', 'azul')
cuisine.group_user_ensure_bsd('wheel', 'azul')

#cuisine.file_attribs('/dev/vboxnetctl',
                     #mode='0660', owner='root', group='vboxusers')

cuisine.run('touch /etc/devfs.conf')
devfs_conf = cuisine.text_ensure_line(cuisine.file_read(
    '/etc/devfs.conf'),
    'own     vboxnetctl root:vboxusers',
    'perm    vboxnetctl 0660')
cuisine.file_write('/etc/devfs.conf', devfs_conf)

cuisine.run('touch /etc/devfs.rules')
devfs_rules = cuisine.text_ensure_line(cuisine.file_read(
    '/etc/devfs.rules'),
    '[system=10]',
    "add path 'usb/*' mode 0660 group operator")
cuisine.file_write('/etc/devfs.rules', devfs_rules)

rc_conf = cuisine.text_ensure_line(cuisine.file_read(
    '/etc/rc.conf'),
    'devfs_system_ruleset="system"')
cuisine.file_write('/etc/rc.conf', rc_conf)

xorg_conf = cuisine.text_ensure_line(cuisine.file_read(
    '/etc/X11/xorg.conf'),
    'Section "ServerFlags"',
    '  Option  "AIGLX" "off"',
    ' EndSection')
cuisine.file_write('/etc/X11/xorg.conf', xorg_conf)

cuisine.run('touch /home/azul/.xinitrc')
cuisine.file_attribs('/home/azul/.xinitrc',
                     mode='0750', owner='azul', group='users')
xinitrc = cuisine.text_ensure_line(cuisine.file_read(
    '/home/azul/.xinitrc'),
    'exec startxfce4')
cuisine.file_write('/home/azul/.xinitrc', xinitrc)
