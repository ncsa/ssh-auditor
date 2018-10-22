FROM alpine
RUN apk update
RUN apk add openssh
RUN ssh-keygen -A
RUN echo -e "\n\n"|adduser test
RUN echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
