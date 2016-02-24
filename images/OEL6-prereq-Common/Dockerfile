FROM s4ragent/rac_on_docker:OEL6-base
MAINTAINER MASAKI OOSHIMA s4ragent
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
#disable services
RUN chkconfig iptables off
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/retmpfs.sh /usr/local/bin/retmpfs.sh
RUN install -o root -g root -m 755 /usr/local/bin/retmpfs.sh /etc/init.d/retmpfs
ENTRYPOINT ["/sbin/init"]
