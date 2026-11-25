FROM vulhub/minio:2023-02-27T18-10-45Z
COPY services/l5-minio/inject.sh /inject.sh
RUN chmod +x /inject.sh
ENTRYPOINT ["/inject.sh"]
CMD ["minio", "server", "--console-address", ":9001", "/data"]
