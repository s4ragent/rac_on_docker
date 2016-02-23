FROM s4ragent/rac_on_docker:OEL6-prereq-Common
MAINTAINER MASAKI OOSHIMA s4ragent
ENV MOUNT_PATH /u01
ENV ORA_ORACLE_BASE /u01/app/oracle
ENV ORA_ORACLE_HOME /u01/app/oracle/product/12.1.0/dbhome_1
ENV GRID_ORACLE_BASE /u01/app/grid
ENV GRID_ORACLE_HOME /u01/app/12.1.0/grid
ENV ORAINVENTORY /u01/app/oraInventory
RUN echo -e "#this is for oracle install#\n\
if [ -t 0 ]; then\n\
        stty intr ^C\n\
fi" >> /home/oracle/.bashrc && \
echo -e "#this is for oracle install#\n\
if [ -t 0 ]; then\n\
        stty intr ^C\n\
fi" >> /home/grid/.bashrc
## .bash_profile ###
RUN echo -e "### for oracle install ####\n\
export ORACLE_BASE=${ORA_ORACLE_BASE}\n\
export ORACLE_HOME=${ORA_ORACLE_HOME}\n\
" >> /home/oracle/.bash_profile
RUN echo -e "export TMPDIR=/tmp\n\
export TEMP=/tmp\n\
export PATH=\$ORACLE_HOME/bin:\$ORACLE_HOME/jdk/bin:\${PATH}\n\
export LD_LIBRARY_PATH=\$ORACLE_HOME/lib\n\
" >> /home/oracle/.bash_profile
RUN echo -e "### for oracle install ####\n\
export ORACLE_BASE=${GRID_ORACLE_BASE}\n\
export ORACLE_HOME=${GRID_ORACLE_HOME}\n\
" >> /home/grid/.bash_profile
RUN echo -e "export TMPDIR=/tmp\n\
export TEMP=/tmp\n\
export PATH=\$ORACLE_HOME/bin:\$ORACLE_HOME/jdk/bin:\${PATH}\n\
export LD_LIBRARY_PATH=\$ORACLE_HOME/lib\n\
" >> /home/grid/.bash_profile
## create oraclehome
RUN  mkdir ${MOUNT_PATH} && \
     chown grid:oinstall ${MOUNT_PATH} && \
     mkdir -p ${GRID_ORACLE_BASE} && \
     mkdir -p ${GRID_ORACLE_HOME} && \
     chown -R grid:oinstall ${MOUNT_PATH} && \
     mkdir -p ${ORA_ORACLE_BASE} && \
     chown oracle:oinstall ${ORA_ORACLE_BASE} && \
     chmod -R 775 ${MOUNT_PATH}
##for nfs
RUN echo -e "### for oracle install ####\n\
nas1:/asm_disk $MOUNT_PATH/asm_disk nfs rw,bg,hard,nointr,tcp,vers=3,timeo=600,rsize=32768,wsize=32768,actimeo=0 0 0 \n\
nas1:/shared_grid $GRID_ORACLE_HOME nfs rw,bg,hard,nointr,tcp,vers=3,timeo=600,rsize=32768,wsize=32768,actimeo=0 0 0 \n\
nas1:/shared_home $ORA_ORACLE_HOME nfs rw,bg,hard,nointr,tcp,vers=3,timeo=600,rsize=32768,wsize=32768,actimeo=0 0 0 \n\
" >> /etc/fstab
RUN mkdir -p $MOUNT_PATH/asm_disk &&\
        mkdir -p $ORA_ORACLE_HOME &&\
        chown grid:oinstall $MOUNT_PATH/asm_disk &&\
        chown oracle:oinstall $ORA_ORACLE_HOME
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/util.sh /root/util.sh
RUN chmod 755 /root/util.sh
RUN echo "/root/util.sh initasmimg" >> /etc/rc.d/rc.local
ENTRYPOINT ["/sbin/init"]
