FROM oraclelinux:6
#installpackages
RUN yum -y install nfs-utils
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
ENTRYPOINT ["/sbin/init"]
