FROM alpine
RUN apk update
RUN apk add openssh
RUN ssh-keygen -A
RUN echo LogLevel DEBUG >> /etc/ssh/sshd_config
RUN echo -e "XXX\nXXX"|adduser test
RUN mkdir /home/test/.ssh
ADD test.pub /home/test/.ssh/authorized_keys
RUN chmod 0700 /home/test /home/test/.ssh && \
    chmod 0600 /home/test/.ssh/authorized_keys && \
    chown test:test /home/test/.ssh /home/test/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-De"]
