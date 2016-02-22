FROM oraclelinux:6
#install epel
RUN rpm -ivh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
#installpackages
RUN yum -y groupinstall Xfce "Japanese Support" &&\
    yum -y install git\
                   traceroute\
                   unzip\
                   iperf\
                   oracle-rdbms-server-12cR1-preinstall\
                   screen\
                   nfs-utils\
                   dnsmasq\
#                   git\
#                   bison\
#                   flex\
#                   db4-devel\
#                   libselinux-python\
#                   python-pip\
#                   ansible\
                   tar\
                   net-tools\
                   expect\
                   bind-utils\
                   xrdp\
                   tigervnc-server\
                   firefox
RUN yum -y reinstall glibc-common
RUN yum -y clean all
RUN mv /etc/init/tty.conf /etc/init/tty.bk; mv /etc/init/serial.conf /etc/init/serial.bk
RUN userdel -r oracle && groupdel dba && groupdel oinstall && \
    groupadd -g 54321 dba && groupadd -g 54322 oinstall && \
    groupadd -g 54323 asmdba && groupadd -g 54324 asmoper && groupadd -g 54325 asmadmin && \
    useradd -u 54321 -g oinstall -G dba,asmdba,asmadmin oracle && \
    useradd -u 54322 -g oinstall -G asmadmin,asmdba,asmoper grid && \
    echo "oracle:oracle123" | chpasswd && \
    echo "grid:grid123" | chpasswd
RUN sed -i 's/oracle/#oracle/' /etc/security/limits.d/oracle-rdbms-server-12cR1-preinstall.conf && \
sed -i 's/oracle/#oracle/' /etc/security/limits.conf && \
echo -e "\n\
oracle - nproc 16384\n\
oracle - nofile 65536\n\
oracle soft stack 10240\n\
grid - nproc 16384\n\
grid - nofile 65536\n\
grid soft stack 10240\n\
" >> /etc/security/limits.conf
#sshkey
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/util.sh /root/util.sh
RUN chmod 755 /root/util.sh
RUN /root/util.sh createsshkey
#xrdp
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/Xclients /etc/skel/.Xclients
RUN chmod +x /etc/skel/.Xclients
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/km-e0010411.ini /etc/xrdp/km-e0010411.ini
RUN cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-0411.ini &&\
    cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-e0200411.ini &&\
    cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-e0210411.ini
#disable services
RUN chkconfig iptables off
ENTRYPOINT ["/sbin/init"]
