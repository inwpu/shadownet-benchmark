FROM vulhub/n8n:1.65.0
COPY services/l2-n8n/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
EXPOSE 5678
ENTRYPOINT ["/docker-entrypoint.sh"]
