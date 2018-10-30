FROM alpine
RUN apk update
RUN apk add openssh
RUN ssh-keygen -A
RUN echo -e "XXX\nXXX"|adduser test
RUN mkdir /home/test/.ssh
ADD test.pub /home/test/.ssh/authorized_keys
RUN chmod 0755 /home/test /home/test/.ssh && \
    chown 0644 /home/test/.ssh/authorized_keys && \
    chown test: /home/test/.ssh /home/test/.ssh/authorized_keys
RUN ls -la /home /home/test /home/test/.ssh
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
