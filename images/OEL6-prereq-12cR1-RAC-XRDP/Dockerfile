FROM s4ragent/rac_on_docker:/OEL6-prereq-12cR1-RAC
RUN yum -y groupinstall Xfce "Japanese Support" &&\
    yum -y install xrdp\
                   tigervnc-server\
                   firefox
RUN yum -y clean all
#xrdp
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/Xclients /etc/skel/.Xclients
RUN chmod +x /etc/skel/.Xclients
ADD https://raw.githubusercontent.com/s4ragent/rac_on_docker/master/km-e0010411.ini /etc/xrdp/km-e0010411.ini
RUN cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-0411.ini &&\
    cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-e0200411.ini &&\
    cp /etc/xrdp/km-e0010411.ini /etc/xrdp/km-e0210411.ini
ENTRYPOINT ["/sbin/init"]
