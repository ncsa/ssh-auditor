FROM alpine
RUN apk update
RUN apk add openssh
RUN ssh-keygen -A
RUN echo -e "test\ntest"|adduser test
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
