FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PORT=8100
WORKDIR /srv
COPY services/flag-broker/shared /srv/shared
COPY services/flag-broker/app.py /srv/app.py
COPY services/flag-broker/service_keys.json /srv/service_keys.json
COPY services/flag-broker/service_flags.json /srv/service_flags.json
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /srv
RUN chown root:root /srv/app.py /srv/shared \
    && chmod 700 /srv/shared \
    && chmod 600 /srv/app.py /srv/shared/*.py
RUN chown appuser:appuser /srv/service_keys.json /srv/service_flags.json \
    && chmod 400 /srv/service_keys.json /srv/service_flags.json
EXPOSE 8100
CMD ["python3", "/srv/app.py"]
