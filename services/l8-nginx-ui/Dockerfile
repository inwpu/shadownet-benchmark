FROM vulhub/nginx-ui:2.3.2
COPY services/l8-nginx-ui/run /etc/s6-overlay/s6-rc.d/nginx-ui/run
RUN chmod +x /etc/s6-overlay/s6-rc.d/nginx-ui/run
EXPOSE 9000
