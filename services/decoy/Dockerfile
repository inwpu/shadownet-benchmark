FROM python:3.11-slim
WORKDIR /app
COPY services/decoy/decoy.py /app/decoy.py
COPY services/decoy/deception.json /app/deception.json
RUN useradd --uid 10003 --create-home --shell /usr/sbin/nologin decoy \
    && chown -R decoy:decoy /app
USER decoy
EXPOSE 8080 8443 2222 3306 5432 6379 9200 27017
CMD ["python3", "/app/decoy.py"]
