FROM alpine
RUN apk update
RUN apk add openssh
RUN ssh-keygen -A
RUN echo -e "test\ntest"|adduser test
RUN rm /usr/bin/id
RUN echo AllowTcpForwarding no >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
