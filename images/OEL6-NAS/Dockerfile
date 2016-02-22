FROM oraclelinux:6
#installpackages
RUN yum -y install nfs-utils
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
## enable service & disable service
RUN chkconfig iptables off
ENTRYPOINT ["/sbin/init"]
