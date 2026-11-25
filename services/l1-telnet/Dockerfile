FROM vulhub/inetutils:2.5
RUN userdel testuser 2>/dev/null || true; \
    echo "root:$(head -c 32 /dev/urandom | base64 | tr -d '/+=')" | chpasswd
EXPOSE 23
CMD ["/usr/sbin/xinetd", "-dontfork"]
