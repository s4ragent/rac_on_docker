#!/bin/bash
LANG=C
ORA_ORACLE_BASE=/u01/app/oracle
ORA_ORACLE_HOME=/u01/app/oracle/product/12.1.0/dbhome_1
GRID_ORACLE_BASE=/u01/app/grid
GRID_ORACLE_HOME=/u01/app/12.1.0/grid
ORAINVENTORY=/u01/app/oraInventory
MOUNT_PATH=/u01
MEDIA_PATH=/media
NODEPREFIX=node
DOMAIN_NAME=public

SCAN_NAME="scan"
CLUSTER_NAME="node-cluster"
DBNAME="ORCL"
SIDNAME="ORCL" 
SYSPASSWORD="oracle123"
SYSTEMPASSWORD="oracle123"
REDOFILESIZE=10
DISKGROUPNAME="CRS"
FRA=$DISKGROUPNAME
ASMPASSWORD="oracle123"
CHARSET="AL32UTF8"
NCHAR="AL16UTF16"
MEMORYTARGET=2400
TEMPLATENAME="General_Purpose.dbc"
DATABASETYPE="MULTIPURPOSE"


release=`rpm -q --whatprovides redhat-release`
rhel_version=`rpm -q "$release" --qf "%{version}"`

getnodename ()
{
  echo "$NODEPREFIX"`printf "%.3d" $1`
}



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
      nodename=`getnodename $i`
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
192.168.0.31 ${SCAN_NAME}.${DOMAIN_NAME} ${SCAN_NAME}
192.168.0.32 ${SCAN_NAME}.${DOMAIN_NAME} ${SCAN_NAME}
192.168.0.33 ${SCAN_NAME}.${DOMAIN_NAME} ${SCAN_NAME}
EOT

for i in `seq 1 64`; do
  IP=`expr 100 + $i`
  nodename=`getnodename $i`
  echo "192.168.0.${IP} $nodename".${DOMAIN_NAME}" $nodename" >> /tmp/hosts
  VIP=`expr 200 + $i`
  vipnodename=$nodename"-vip"
  echo "192.168.0.${VIP} $vipnodename".${DOMAIN_NAME}" $vipnodename" >> /tmp/hosts
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
Description=preoracle
Requires=network.target
Before=network.target remote-fs.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/preoracle.sh start
ExecStop=/usr/local/bin/preoracle.sh stop
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

createbase(){
    installpackages
    createuser
    enableping
    createdns
    createrules
    createpreoracle
}

createcontainer(){
    docker run --privileged=true -d --name racbase$1 oraclelinux:$1 /sbin/init
    docker exec -i racbase$1 /bin/bash -c 'cat >/root/create_racbase.sh createbase' <./create_racbase.sh
    docker stop racbase$1
    docker commit racbase test:racbase$1
}

docker_ip(){
#$1 container name
#$2 brigde name
#$3 container's inf name
#$4 ip addr
#$5 add gateway or not
#ex xxx.sh node1 docker1 eth1 192.168.0.101/24
gateway=`ip addr show $2 | grep "inet " | awk -F '[/ ]' '{print $6}'`
mtu=`ip link show $2 | grep mtu | awk '{print $5}'`
pid=`docker inspect -f '{{.State.Pid}}' $1`
mkdir -p /var/run/netns
ln -s /proc/${pid}/ns/net /var/run/netns/${pid}
veth=`perl -e 'print sprintf("%2.2x%2.2x%2.2x", rand()*255, rand()*255, rand()*255)'`

ip link add vethb${veth} type veth peer name vethc${veth}

brctl addif $2 vethb${veth}
ip link set vethb${veth} up
ip link set vethb${veth} mtu $mtu

ip link set vethc${veth} netns ${pid}
ip netns exec ${pid} ip link set vethc${veth} down
ip netns exec ${pid} ip link set dev vethc${veth} name $3
ip netns exec ${pid} ip link set $3 up

vmac=`perl -e 'print sprintf("00:16:3e:%2.2x:%2.2x:%2.2x", rand()*255, rand()*255, rand()*255)'`
ip netns exec ${pid} ip link set $3 address $vmac
ip netns exec ${pid} ip link set $3 mtu $mtu
ip netns exec ${pid} ip addr add $4 dev $3
if [ "$5" == "gw" ] ; then
  ip netns exec ${pid} ip route add default via $gateway
fi
}

#$1 node number $2 OEL version
createnode(){
    nodename=`getnodename $1`
    IP=`expr 100 + $1`
    mkdir -p /docker/$nodename
    qemu-img create -f raw -o size=20G /docker/$nodename/orahome.img
    mkfs.ext4 -F /docker/$nodename/orahome.img
    setuploop $IP /docker/$nodename/orahome.img
    docker run --privileged=true -d -h ${nodename}.${DOMAIN_NAME} --dns=127.0.0.1 -v /lib/modules:/lib/modules -v /docker/media:/media test:racbase$2 /sbin/init
    docker_ip $nodename brvxlan0 eth1 192.168.0.${IP}/24
    docker_ip $nodename brvxlan1 eth2 192.168.100.${IP}/24
    sleep 35
    docker exec -ti $nodename /bin/bash -c 'mkdir /u01'
    docker exec -i $nodename /bin/bash -c 'cat >>/etc/fstab' < echo "/dev/loop${IP} /u01 ext4 defaults 0 0"
    #docker exec -ti $nodename /bin/bash -c 'echo "/dev/loop32 /u01 ext4 defaults 0 0" >> /etc/fstab'
    docker exec -ti $nodename /bin/bash -c 'mount -a'
    docker exec -ti $nodename sh /root/create_racbase.sh createoraclehome


    
    
}

setuploop(){
    initloop $1
    cnt=0
    while true; do
        losetup /dev/loop$1 $2
        if [ $? -eq 0 ]; then
            break
        fi
        if [ $cnt -eq 10 ]; then
            echo "10 times losetup failed"
            break
        fi
    cnt=`expr $cnt + 1 `
    sleep 3
    done
}


initloop(){
    if [ -e /dev/loop$1 ]; then
        break
    else
        mknod /dev/loop$1 b 7 $1
        chown --reference=/dev/loop0 /dev/loop$1
        chmod --reference=/dev/loop0 /dev/loop$1
    fi
}

creatersp()
{
    NODECOUNT=1
    for i in `seq 1 $1`;
    do
      NODENAME=`getnodename $i`
      if [ $NODECOUNT = 1 ] ; then
        CLUSTERNODES="${NODENAME}:${NODENAME}-vip"
      else
        CLUSTERNODES="$CLUSTERNODES,${NODENAME}:${NODENAME}-vip"
      fi
      NODECOUNT=`expr $NODECOUNT + 1`
    done
    
    NODECOUNT=1
    for i in `seq 1 $1`;
	do
		if [ $NODECOUNT = 1 ] ; then
			DB_CLUSTER_NODES=`getnodename $NODECOUNT`
		else
			DB_CLUSTER_NODES="$DB_CLUSTER_NODES,`getnodename $NODECOUNT`"
		fi
			NODECOUNT=`expr $NODECOUNT + 1`
	done
    
    
    cat > /home/grid/asm.rsp <<EOF
oracle.assistants.asm|S_ASMPASSWORD=$ASMPASSWORD
oracle.assistants.asm|S_ASMMONITORPASSWORD=$ASMPASSWORD
EOF

    cat > /home/grid/grid.rsp  <<EOF
oracle.install.responseFileVersion=/oracle/install/rspfmt_crsinstall_response_schema_v12.1.0
ORACLE_HOSTNAME=
INVENTORY_LOCATION=$ORAINVENTORY
SELECTED_LANGUAGES=en,ja
oracle.install.option=CRS_CONFIG
ORACLE_BASE=$GRID_ORACLE_BASE
ORACLE_HOME=$GRID_ORACLE_HOME
oracle.install.asm.OSDBA=asmdba
oracle.install.asm.OSOPER=asmoper
oracle.install.asm.OSASM=asmadmin
oracle.install.crs.config.gpnp.scanName=${SCAN_NAME}.${DOMAIN_NAME}
oracle.install.crs.config.gpnp.scanPort=1521
oracle.install.crs.config.ClusterType=STANDARD
oracle.install.crs.config.clusterName=${CLUSTER_NAME}
oracle.install.crs.config.gpnp.configureGNS=false
oracle.install.crs.config.autoConfigureClusterNodeVIP=
oracle.install.crs.config.gpnp.gnsOption=
oracle.install.crs.config.gpnp.gnsClientDataFile=
oracle.install.crs.config.gpnp.gnsSubDomain=
oracle.install.crs.config.gpnp.gnsVIPAddress=
oracle.install.crs.config.clusterNodes=$CLUSTERNODES
oracle.install.crs.config.networkInterfaceList=eth0:172.17.0.0:3,eth1:192.168.0.0:1,eth2:192.168.100.0:2
oracle.install.crs.config.storageOption=LOCAL_ASM_STORAGE
oracle.install.crs.config.sharedFileSystemStorage.votingDiskLocations=
oracle.install.crs.config.sharedFileSystemStorage.votingDiskRedundancy=
oracle.install.crs.config.sharedFileSystemStorage.ocrLocations=
oracle.install.crs.config.sharedFileSystemStorage.ocrRedundancy=
oracle.install.crs.config.useIPMI=false
oracle.install.crs.config.ipmi.bmcUsername=
oracle.install.crs.config.ipmi.bmcPassword=
oracle.install.asm.SYSASMPassword=$ASMPASSWORD
oracle.install.asm.diskGroup.name=$DISKGROUPNAME
oracle.install.asm.diskGroup.redundancy=EXTERNAL
oracle.install.asm.diskGroup.AUSize=1
oracle.install.asm.diskGroup.disks=/dev/loop30
oracle.install.asm.diskGroup.diskDiscoveryString=/dev/loop*
oracle.install.asm.monitorPassword=$ASMPASSWORD
oracle.install.asm.ClientDataFile=
oracle.install.crs.config.ignoreDownNodes=false
oracle.install.config.managementOption=NONE
oracle.install.config.omsHost=
oracle.install.config.omsPort=
oracle.install.config.emAdminUser=
EOF

cat >/home/oracle/db.rsp <<EOF
oracle.install.responseFileVersion=/oracle/install/rspfmt_dbinstall_response_schema_v12.1.0
oracle.install.option=INSTALL_DB_SWONLY
ORACLE_HOSTNAME=
UNIX_GROUP_NAME=oinstall
INVENTORY_LOCATION=
SELECTED_LANGUAGES=en,ja
ORACLE_HOME=$ORA_ORACLE_HOME
ORACLE_BASE=$ORA_ORACLE_BASE
oracle.install.db.InstallEdition=EE
oracle.install.db.DBA_GROUP=dba
oracle.install.db.OPER_GROUP=oper
oracle.install.db.BACKUPDBA_GROUP=dba
oracle.install.db.DGDBA_GROUP=dba
oracle.install.db.KMDBA_GROUP=dba
oracle.install.db.rac.configurationType=
oracle.install.db.CLUSTER_NODES=$DB_CLUSTER_NODES
oracle.install.db.isRACOneInstall=
oracle.install.db.racOneServiceName=
oracle.install.db.rac.serverpoolName=
oracle.install.db.rac.serverpoolCardinality=
oracle.install.db.config.starterdb.type=
oracle.install.db.config.starterdb.globalDBName=
oracle.install.db.config.starterdb.SID=
oracle.install.db.ConfigureAsContainerDB=
oracle.install.db.config.PDBName=
oracle.install.db.config.starterdb.characterSet=
oracle.install.db.config.starterdb.memoryOption=
oracle.install.db.config.starterdb.memoryLimit=
oracle.install.db.config.starterdb.installExampleSchemas=
oracle.install.db.config.starterdb.password.ALL=
oracle.install.db.config.starterdb.password.SYS=
oracle.install.db.config.starterdb.password.SYSTEM=
oracle.install.db.config.starterdb.password.DBSNMP=
oracle.install.db.config.starterdb.password.PDBADMIN=
oracle.install.db.config.starterdb.managementOption=
oracle.install.db.config.starterdb.omsHost=
oracle.install.db.config.starterdb.omsPort=
oracle.install.db.config.starterdb.emAdminUser=
oracle.install.db.config.starterdb.emAdminPassword=
oracle.install.db.config.starterdb.enableRecovery=
oracle.install.db.config.starterdb.storageType=
oracle.install.db.config.starterdb.fileSystemStorage.dataLocation=
oracle.install.db.config.starterdb.fileSystemStorage.recoveryLocation=
oracle.install.db.config.asm.diskGroup=
oracle.install.db.config.asm.ASMSNMPPassword=
MYORACLESUPPORT_USERNAME=
MYORACLESUPPORT_PASSWORD=
SECURITY_UPDATES_VIA_MYORACLESUPPORT=
DECLINE_SECURITY_UPDATES=
PROXY_HOST=
PROXY_PORT=
PROXY_USER=
PROXY_PWD=
EOF
    chmod 755 /home/grid/grid.rsp
    chmod 755 /home/grid/asm.rsp
    chown grid.oinstall /home/grid/grid.rsp
    chown grid.oinstall /home/grid/asm.rsp
    
    chmod 755 /home/oracle/db.rsp
    chown oracle.oinstall /home/oracle/db.rsp
}

grid_install(){
	ssh -i gridkey/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null grid@192.168.0.101 "/media/grid/runInstaller -silent -responseFile /home/grid/grid.rsp -ignoreSysPrereqs -ignorePrereq"
}

exedbca(){
	dbcaoption="-silent -createDatabase -templateName $TEMPLATENAME -gdbName $DBNAME -sid $SIDNAME" 
	dbcaoption="$dbcaoption -SysPassword $SYSPASSWORD -SystemPassword $SYSTEMPASSWORD -emConfiguration NONE -redoLogFileSize $REDOFILESIZE"
	dbcaoption="$dbcaoption -recoveryAreaDestination $FRA -storageType ASM -asmSysPassword $ASMPASSWORD -diskGroupName $DISKGROUPNAME"
	dbcaoption="$dbcaoption -characterSet $CHARSET -nationalCharacterSet $NCHAR -totalMemory $MEMORYTARGET -databaseType $DATABASETYPE"

    NODECOUNT=1
    for i in `seq 1 $1`;
	do
		if [ $NODECOUNT = 1 ] ; then
			dbcaoption="$dbcaoption -nodelist `getnodename $NODECOUNT`"
		else
			dbcaoption="$dbcaoption,`getnodename $NODECOUNT`"
		fi
			NODECOUNT=`expr $NODECOUNT + 1`
	done

	ssh -i oraclekey/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null oracle@192.168.0.101 "$ORA_ORACLE_HOME/bin/dbca $dbcaoption"
}

exeasmca(){
    ssh -i gridkey/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null grid@192.168.0.101 "$GRID_ORACLE_HOME/cfgtoollogs/configToolAllCommands RESPONSE_FILE=/home/grid/asm.rsp"
}

exegridrootsh(){
    NODECOUNT=1
    for i in `seq 1 $1`;
	do
	    docker exec -ti `getnodename $NODECOUNT` $ORAINVENTORY/orainstRoot.sh
	done
    
    docker exec -ti `getnodename 1` $GRID_ORACLE_HOME/root.sh
    for i in `seq 2 $1`;
	do
	    docker exec -ti `getnodename 1` $GRID_ORACLE_HOME/root.sh &
	    #sleep 30s
	done
}
db_install(){
	ssh -i oraclekey/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null oracle@192.168.0.101 "/media/database/runInstaller -silent -responseFile /home/oracle/db.rsp -ignoreSysPrereqs -ignorePrereq"
}

exeorarootsh(){
    	NODECOUNT=1
    	for i in `seq 1 $1`;
	do
	    docker exec -ti `getnodename $NODECOUNT` $ORA_ORACLE_HOME/orainstRoot.sh
	done
}

gridstatus(){
    docker exec -ti `getnodename 1` $GRID_ORACLE_HOME/bin/crsctl status resource -t
}

#$1 count of nodes $2 OEL version
nodeinstalldbca(){
	for i in `seq 1 $1`;
	do
	    createnode $i $2
	done
	
        createshareddisk
        
        nodename=`getnodename 1`
        docker cp  ${nodename}:/home/oracle/.ssh/id_rsa  oraclekey
        docker cp  ${nodename}:/home/grid/.ssh/id_rsa  gridkey
        
        grid_install
        exegridrootsh
        exeasmca
        gridstatus
        db_install
	exeorarootsh
	exedbca
	gridstatus
}

createshareddisk(){
	mkdir -p /docker/share
	qemu-img create -f raw -o size=20G /docker/share/share.img
	setuploop 30 /docker/share/share.img
	dd if=/dev/zero of=/dev/loop30 bs=1M count=100
}


case "$1" in
  "createoraclehome" ) shift;createoraclehome $*;;
  "createsshkey" ) shift;createsshkey $*;;
  "createbase" ) shift;createbase $*;;
  "createcontainer" shift;createcontainer $*;;
  "createnode" shift;createnode $*;;
  "nodeinstalldbca" shift;nodeinstalldbca $*;;
  * ) echo "Ex " ;;
esac
