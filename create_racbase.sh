#!/bin/bash
source ./common.sh
release=`rpm -q --whatprovides redhat-release`
rhel_version=`rpm -q "$release" --qf "%{version}"`

installpackages(){
case "$rhel_version" in
    7*)
      yum --enablerepo=ol7_addons install oracle-rdbms-server-12cR1-preinstall tar net-tools expect dnsmasq bind-utils -y
      ;;
    6*)
      yum install oracle-rdbms-server-12cR1-preinstall tar net-tools expect dnsmasq bind-utils -y
      ;;
    5*)
      yum install oracle-rdbms-server-12cR1-preinstall tar net-tools expect dnsmasq bind-utils -y
      ;;
    *) exit;;
esac
}

createuser(){
  ###delete user ###
  userdel -r oracle
  userdel -r grid
  groupdel dba
  groupdel oinstall
  groupdel oper
  groupdel asmadmin
  groupdel asmdba
  groupdel asmoper

##create user/group####
  groupadd -g 601 oinstall
  groupadd -g 602 dba
  groupadd -g 603 oper
  groupadd -g 1001 asmadmin
  groupadd -g 1002 asmdba
  groupadd -g 1003 asmoper
  useradd -u 501 -m -g oinstall -G dba,oper,asmdba -d /home/oracle -s /bin/bash -c"Oracle Software Owner" oracle
  useradd -u 1001 -m -g oinstall -G asmadmin,asmdba,asmoper -d /home/grid -s /bin/bash -c "Grid Infrastructure Owner" grid

### edit bash &bashrc ###
   cat >> /home/oracle/.bashrc <<'EOF'
#this is for oracle install#
if [ -t 0 ]; then
   stty intr ^C
fi
EOF

  cat >> /home/grid/.bashrc <<'EOF'
#this is for oracle install#
if [ -t 0 ]; then
   stty intr ^C
fi
EOF

  cat >> /home/oracle/.bash_profile <<EOF
### for oracle install ####
export ORACLE_BASE=${ORA_ORACLE_BASE}
export ORACLE_HOME=${ORA_ORACLE_HOME}
EOF

  cat >> /home/oracle/.bash_profile <<'EOF'
export TMPDIR=/tmp
export TEMP=/tmp
export PATH=$ORACLE_HOME/bin:$ORACLE_HOME/jdk/bin:${PATH}
export LD_LIBRARY_PATH=$ORACLE_HOME/lib
EOF

  cat >> /home/grid/.bash_profile <<EOF
### for grid install####
export ORACLE_BASE=${GRID_ORACLE_BASE}
export ORACLE_HOME=${GRID_ORACLE_HOME}
EOF

  cat >> /home/grid/.bash_profile <<'EOF'
export TMPDIR=/tmp
export TEMP=/tmp
export PATH=$ORACLE_HOME/bin:$ORACLE_HOME/jdk/bin:${PATH}
export LD_LIBRARY_PATH=$ORACLE_HOME/lib
EOF
}

createsshkey(){
  mkdir -p /work/
  ssh-keygen -t rsa -P "" -f /work/id_rsa

  for user in oracle grid
  do
    mkdir /home/$user/.ssh
    cat /work/id_rsa.pub >> /home/$user/.ssh/authorized_keys
    cp /work/id_rsa /home/$user/.ssh/
    
    for i in `seq 1 64`; do
      IP=`expr 100 + $i`
      nodename="node"`printf "%.3d" $i`
      ssh-keyscan -t rsa localhost | sed "s/localhost/${nodename},192.168.0.${IP}/" >> /work/known_hosts
    done
    
  cp /work/known_hosts /home/$user/.ssh
  chown -R ${user}.oinstall /home/$user/.ssh
  chmod 700 /home/$user/.ssh
  chmod 600 /home/$user/.ssh/*
  done
  
  rm -rf /work
}

enableping(){
  chmod u+s /usr/bin/ping
}

createdns(){
cp /etc/hosts /tmp/hosts
sed -i.bak 's:/etc/hosts:/tmp/hosts:g' /lib64/libnss_files.so.2
cat << EOT >> /tmp/hosts
192.168.0.31 scan.public scan
192.168.0.32 scan.public scan
192.168.0.33 scan.public scan
EOT

for i in `seq 1 64`; do
  IP=`expr 100 + $i`
  nodename="node"`printf "%.3d" $i`
  echo "192.168.0.${IP} $nodename".public" $nodename" >> /tmp/hosts
  VIP=`expr 200 + $i`
  vipnodename=$nodename"-vip"
  echo "192.168.0.${VIP} $vipnodename".public" $vipnodename" >> /tmp/hosts
done

#http://qiita.com/inokappa/items/89ab9b7f39bc1ad2f197
#yum -y install dnsmasq bind-utils

cat << EOT >> /etc/dnsmasq.conf
listen-address=127.0.0.1
resolv-file=/etc/resolv.dnsmasq.conf
conf-dir=/etc/dnsmasq.d
user=root
addn-hosts=/tmp/hosts
EOT

cat << EOT >> /etc/resolv.dnsmasq.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOT

case "$rhel_version" in
    7*)
      systemctl enable dnsmasq
      ;;
    6*)
      chkconfig dnsmasq on
      ;;
    5*)
      chkconfig dnsmasq on
      ;;
    *) exit;;
esac
}

createrules()
{
  cat >/etc/udev/rules.d/90-oracle.rules <<'EOF'
KERNEL=="loop3[0-9]", OWNER:="grid", GROUP:="asmadmin", MODE:="666"
EOF
}

createpreoracle6(){
  install -o root -g root -m 755 /usr/local/bin/preoracle.sh /etc/init.d/preoracle
  chkconfig preoracle on
}

createpreoracle7(){
  cat > /etc/systemd/system/preoracle.service<<'EOF'
[Unit]
Description=pre network
Requires=network.target
Before=network.target remote-fs.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/preoracle.sh
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable preoracle.service
}

createpreoraclefile(){
cat >/usr/local/bin/preoracle.sh <<'EOF'
#!/bin/bash
# preoracle     preoracle init configuration
# chkconfig:    2345 20 80
# version:      0.1
# author:       s4ragent
PRELOG=/var/log/preoracle.log
case "$1" in
  start)
    touch /var/lock/subsys/preoracle
    /bin/sleep 30s >>$PRELOG 2>&1
    /bin/umount /dev/shm >>$PRELOG 2>&1
    /bin/mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size=1200m tmpfs /dev/shm >>$PRELOG 2>&1
    exit 0
    ;;
  stop)
    rm -f /var/lock/subsys/preoracle
    ;;                                                                                                                                                                     
esac
EOF
chmod 0700 /usr/local/bin/preoracle.sh
}

createpreoracle(){
case "$rhel_version" in
    7*)
        createpreoraclefile
        createpreoracle7
        ;;
    6*)
        createpreoraclefile
        createpreoracle6
        ;;
    5*)
        createpreoraclefile
        createpreoracle6
        ;;
    *) exit;;
esac
}

createoraclehome(){
    mkdir -p ${GRID_ORACLE_BASE}
    mkdir -p ${GRID_ORACLE_HOME}
    mkdir -p ${MEDIA_PATH}
    chown -R grid:oinstall ${MOUNT_PATH}
    mkdir -p ${ORA_ORACLE_BASE}
    chown oracle:oinstall ${ORA_ORACLE_BASE}
    chmod -R 775 ${MOUNT_PATH}
}

