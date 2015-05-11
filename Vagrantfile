Vagrant.configure("2") do |c|

  c.vm.define :freebsd do |f|
    f.vm.box = "opscode-freebsd-10.1"
    f.vm.box_url = "https://opscode-vm-bento.s3.amazonaws.com/vagrant/virtualbox/opscode_freebsd-10.1_chef-provisionerless.box"
    f.vm.hostname = "freebsd-10.1"
    f.ssh.shell = '/bin/sh'
    f.vm.network(:private_network, {:ip=>"192.168.33.2"})
    f.vm.synced_folder ".", "/vagrant", disabled: true
    f.vm.synced_folder "/home/azul/gits/azulinho-cuisine", "/vagrant", create: true, type: :nfs, :mount_options => ['nolock,vers=3,tcp,noatime,clientaddr=192.168.33.2']
    f.vm.provider :virtualbox do |p|
      p.gui = true
    end
    f.vm.provision :shell, path: 'tests/freebsd/bootstrap.sh'
  end

  c.vm.define :ubuntu do |f|
    f.vm.box = "opscode-ubuntu-14.04"
    f.vm.box_url = "http://opscode-vm-bento.s3.amazonaws.com/vagrant/virtualbox/opscode_ubuntu-14.04_chef-provisionerless.box"
    f.vm.hostname = "ubuntu-14.04"
    f.ssh.shell = '/bin/bash'
    f.vm.network(:private_network, {:ip=>"192.168.33.3"})
    f.vm.synced_folder ".", "/vagrant", disabled: true
    f.vm.synced_folder "/home/azul/gits/azulinho-cuisine", "/vagrant", create: true, type: :nfs, :mount_options => ['nolock,vers=3,tcp,noatime,clientaddr=192.168.33.3']
    f.vm.provider :virtualbox do |p|
      p.gui = false
    end
    f.vm.provision :shell, inline: 'test -e /usr/bin/gcc || ( apt-get update && sudo apt-get -o APT::Install-Suggests="true" -y install build-essential python-dev python-gmpy2)'
    f.vm.provision :shell, inline: 'test -e /usr/bin/easy_install || apt-get -y install python-setuptools'
    f.vm.provision :shell, inline: 'test -e /usr/bin/fabric || easy_install fabric'
    f.vm.provision :shell, inline: 'python /vagrant/tests/ubuntu/all.py'
  end


end
