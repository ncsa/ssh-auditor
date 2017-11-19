FROM alpine
RUN apk update
RUN apk add openssh
RUN ssh-keygen -A
RUN echo -e "test\ntest"|adduser test
RUN rm /usr/bin/id
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
