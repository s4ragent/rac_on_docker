FROM oraclelinux:6
#installpackages
RUN yum -y install nfs-utils
                   nfs-utils\
                   dnsmasq\
                   tar\
                   net-tools\
                   expect\
                   bind-utils
## for NFS
RUN mkdir /asm_disk &&\
mkdir /shared_grid &&\
mkdir /shared_home 
RUN echo -e "#for asm#\n\
/asm_disk *(rw,sync,no_wdelay,insecure_locks,no_root_squash) \n\
/shared_grid *(rw,sync,no_wdelay,insecure_locks,no_root_squash) \n\
/shared_home *(rw,sync,no_wdelay,insecure_locks,no_root_squash) \n\
" >> /etc/exports
RUN chkconfig nfs on
RUN echo "/etc/init.d/nfs restart" >> /etc/rc.d/rc.local
#disable tty
RUN mv /etc/init/tty.conf /etc/init/tty.bk; mv /etc/init/serial.conf /etc/init/serial.bk
#for dnsmasq
RUN echo -e "listen-address=127.0.0.1\n\
resolv-file=/etc/resolv.dnsmasq.conf\n\
conf-dir=/etc/dnsmasq.d\n\
user=root\n\
addn-hosts=/tmp/hosts\n\
" >> /etc/dnsmasq.conf
RUN echo -e "nameserver 8.8.8.8\n\
nameserver 8.8.4.4\n\
" >> /etc/resolv.dnsmasq.conf
## OEL7 systemctl enable dnsmasq
## OEL6 chkconfig dnsmasq on
RUN chkconfig dnsmasq on
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/util.sh /root/util.sh
RUN chmod 755 /root/util.sh
RUN /root/util.sh createhosts
## enable service & disable service
RUN chkconfig iptables off
ENTRYPOINT ["/sbin/init"]
