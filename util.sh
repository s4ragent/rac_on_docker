NODEPREFIX="node"
DOMAIN_NAME="public"
SCAN_NAME="scan"

NAS_BASE_IP=10
SCAN_BASE_IP=20
DB_BASE_IP=30
OEM_BASE_IP=40
CLIENT_BASE_IP=50
HOST_BASE_IP=60
NODE_BASE_IP=70
BASE_IP=$NODE_BASE_IP


NETWORKS=("192.168.222.0" "192.168.223.0" "192.168.224.0" "192.168.225.0")
HOSTFILE=/tmp/hosts

changehostname()
{
	oel_version=`rpm -q oraclelinux-release --qf "%{version}"`
	NEW_HOSTNAME="$1.$DOMAIN_NAME"
	case "$oel_version" in
    		6*)
		sed -i "s/HOSTNAME=.*/HOSTNAME=$NEW_HOSTNAME/g" /etc/sysconfig/network
        	;;
    		7*)
		echo "$NEW_HOSTNAME" > /etc/hostname
        	;;	
	esac
}

getnumber()
{
	nodenumber=`echo $1 | grep -Po  '[1-9]{1,3}'`
	case "$1" in
        	nas*)
                	echo `expr $NAS_BASE_IP + $nodenumber`;
                	;;
        	scan*)
                	echo `expr $SCAN_BASE_IP + $nodenumber`;
                	;;
        	db*)
                	echo `expr $DB_BASE_IP + $nodenumber`;
                	;;
        	oem*)
                	echo `expr $OEM_BASE_IP + $nodenumber`;
                	;;
        	client*)
                	echo `expr $CLIENT_BASE_IP + $nodenumber`;
                	;;
        	host*)
                	echo `expr $HOST_BASE_IP + $nodenumber`; 
                	;;
        	node*)
                	echo `expr $NODE_BASE_IP + $nodenumber`;                
        		;;
	esac
}


getnodename ()
{
	echo "$NODEPREFIX"`printf "%.3d" $1`;
}

getip () {
	SEGMENT=`echo ${NETWORKS[$1]} | grep -Po '\d{1,3}\.\d{1,3}\.\d{1,3}\.'`; 
	if [ $2 == "real" ] ; then 
		IP=`expr $BASE_IP + $3`; 
		echo "${SEGMENT}${IP}";
	elif [ $2 == "vip" ] ; then 
		IP=`expr $BASE_IP + 100 + $3`; 
		echo "${SEGMENT}${IP}";
	elif [ $2 == "host" ] ; then 
		IP=`expr $HOST_BASE_IP + $3`;
		echo "${SEGMENT}${IP}";
	elif [ $2 == "scan" ] ; then
		echo "${SEGMENT}`expr $SCAN_BASE_IP + 1` ${SCAN_NAME}.${DOMAIN_NAME} ${SCAN_NAME}";
		echo "${SEGMENT}`expr $SCAN_BASE_IP + 2` ${SCAN_NAME}.${DOMAIN_NAME} ${SCAN_NAME}";
		echo "${SEGMENT}`expr $SCAN_BASE_IP + 3` ${SCAN_NAME}.${DOMAIN_NAME} ${SCAN_NAME}";
	elif [ $2 == "nas" ] ; then
		echo "${SEGMENT}`expr $NAS_BASE_IP + 1` nas1.${DOMAIN_NAME} nas1";
		echo "${SEGMENT}`expr $NAS_BASE_IP + 2` nas2.${DOMAIN_NAME} nas2";
		echo "${SEGMENT}`expr $NAS_BASE_IP + 3` nas3.${DOMAIN_NAME} nas3";
	elif [ $2 == "other" ] ; then
		echo "${SEGMENT}`expr $DB_BASE_IP + 1` db1.${DOMAIN_NAME} db1";
		echo "${SEGMENT}`expr $DB_BASE_IP + 2` db2.${DOMAIN_NAME} db2";
		echo "${SEGMENT}`expr $DB_BASE_IP + 3` db3.${DOMAIN_NAME} db3";
		echo "${SEGMENT}`expr $DB_BASE_IP + 4` db4.${DOMAIN_NAME} db4";
		echo "${SEGMENT}`expr $OEM_BASE_IP + 1` oem1.${DOMAIN_NAME} oem1";
		echo "${SEGMENT}`expr $OEM_BASE_IP + 2` oem2.${DOMAIN_NAME} oem2";						
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 1` client1.${DOMAIN_NAME} client1";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 2` client2.${DOMAIN_NAME} client2";		
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 3` client3.${DOMAIN_NAME} client3";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 4` client4.${DOMAIN_NAME} client4";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 5` client5.${DOMAIN_NAME} client5";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 6` client6.${DOMAIN_NAME} client6";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 7` client7.${DOMAIN_NAME} client7";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 8` client8.${DOMAIN_NAME} client0";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 9` client9.${DOMAIN_NAME} client9";
		echo "${SEGMENT}`expr $CLIENT_BASE_IP + 10` client10.${DOMAIN_NAME} client10";
	fi;
}

#$1 network number $2 hostname
getipfromhost(){
	local nodenumber=`getnumber $2`
	nodenumber=`expr $nodenumber - $BASE_IP`
	getip $1 real $nodenumber
}

createhosts()
{
	cat > $HOSTFILE <<EOF
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

	getip 0 scan >> $HOSTFILE
	getip 3 nas >> $HOSTFILE
	getip 0 other >> $HOSTFILE
	for i in `seq 1 64`; do 
		nodename=`getnodename $i`;
		echo "`getip 0 real $i` $nodename".${DOMAIN_NAME}" $nodename" >> $HOSTFILE;
		vipnodename=$nodename"-vip";
		vipi=`expr $i + 100`;
		echo "`getip 0 real $vipi` $vipnodename".${DOMAIN_NAME}" $vipnodename" >> $HOSTFILE;
	done
}

createsshkey()
{
/etc/init.d/sshd start
WORK_DIR=/work
mkdir -p $WORK_DIR

ssh-keygen -t rsa -P "" -f /work/id_rsa
hostkey=`cat /etc/ssh/ssh_host_rsa_key.pub`
for i in `seq 1 64`; do
    nodename=`getnodename $i`
    ip=`expr $BASE_IP + $i`
    echo "${nodename},`getip 0 real $i` $hostkey" >> /work/known_hosts
done

for user in oracle grid
do
	mkdir /home/$user/.ssh
	cat /work/id_rsa.pub >> /home/$user/.ssh/authorized_keys
	cp /work/id_rsa /home/$user/.ssh/
	cp /work/known_hosts /home/$user/.ssh
	chown -R ${user}.oinstall /home/$user/.ssh
	chmod 700 /home/$user/.ssh
	chmod 600 /home/$user/.ssh/*
done
	rm -rf $WORK_DIR/id_rsa $WORK_DIR/id_rsa.pub $WORK_DIR/known_hosts
}

setlangja()
{
	echo "export LANG=ja_JP.UTF-8" >> /home/oracle/.bash_profile
	echo "export LANG=ja_JP.UTF-8" >> /home/grid/.bash_profile
}

initasmimg()
{
	nfscount=`mount | grep asm_disk | wc -l`
	if [ ! -e /u01/asm_disk/asm01.img -a $nfscount -gt 0 ] ; then
		dd if=/dev/zero of=/u01/asm_disk/asm01.img bs=1M count=`expr 20 \* 1024`
		chmod 0660 /u01/asm_disk/asm01.img
		chown -R grid:oinstall /u01/asm_disk
		source /home/grid/.bash_profile
		chown -R grid:oinstall $ORACLE_HOME
		source /home/oracle/.bash_profile
		chown -R oracle:oinstall $ORACLE_HOME
        fi
}

createnetwork(){
        for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
        do
		docker network create --subnet=${NETWORKS[$k]}/24 rac$k
        done
}

#$1 hostname $2 OEL VER $3 Oracle VER
createnode(){
	case "$1" in
        	nas*)
        		docker run --privileged -d -h $1.${DOMAIN_NAME} --name $1 s4ragent/rac_on_docker:OEL6-NAS
        		docker exec -ti $1 sed -i "s/listen-address=127.0.0.1/listen-address=`getipfromhost 3 $1`/g" /etc/dnsmasq.conf
                	;;
        	db*)
                	;;
        	oem*)
                	;;
        	client*)
                	;;
        	node001)
                	docker run --privileged -p 3389:3389 -d -h $1.${DOMAIN_NAME}  --name $1 --dns=`getipfromhost 3 nas1` --dns-search=${DOMAIN_NAME} -v /lib/modules:/lib/modules -v /docker/media:/media s4ragent/rac_on_docker:OEL$2-prereq-$3-RAC
        		;;
        	node*)
                	docker run --privileged -d -h $1.${DOMAIN_NAME}  --name $1 --dns=`getipfromhost 3 nas1` --dns-search=${DOMAIN_NAME} -v /lib/modules:/lib/modules -v /docker/media:/media s4ragent/rac_on_docker:OEL$2-prereq-$3-RAC                
        		;; 
	esac
	for (( k = 0; k < ${#NETWORKS[@]}; ++k ))
        do
		docker network connect --ip `getipfromhost $k $1` rac$k $1
        done
        if [ "$2" != "7" ] ; then
		docker exec -ti $1 hostname ${1}.${DOMAIN_NAME}
		docker exec -ti $1 sed -i "s/localhost.localdomain/${1}.${DOMAIN_NAME}/g" /etc/sysconfig/network
	fi
        for i in $(seq 1 30) ; do echo -n "#"; sleep 1  ; done
}

#$1 node_count $2 OEL VER $3 Oracle VER
createall()
{
	createnetwork
	createnode nas1 6 
	for i in `seq 1 $1`; do
    		createnode `getnodename $i` $2 $3
	done 
}

case "$1" in
  "createhosts" ) shift;createhosts $*;;
  "createsshkey" ) shift;createsshkey $*;;
  "getnumber" ) shift;getnumber $*;;
  "changehostname" ) shift;changehostname $*;;  
  "setlangja" ) shift;setlangja $*;;
  "initasmimg" ) shift;initasmimg $*;;
  "createnetwork" ) shift;createnetwork $*;;
  "getipfromhost") shift;getipfromhost $*;;
  "createnode" ) shift;createnode $*;;
  "createall" ) shift;createall $*;;
esac
