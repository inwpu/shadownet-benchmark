FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PORT=8000
WORKDIR /srv
COPY services/b2-router/shared /srv/shared
RUN mkdir -p /srv/files && echo "public export" > /srv/files/readme.txt \
    && pip install --no-cache-dir cryptography==41.0.7 \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /srv
COPY services/b2-router/app.py /srv/app.py
RUN chown root:root /srv/app.py /srv/shared \
    && chmod 700 /srv/shared \
    && chmod 600 /srv/app.py /srv/shared/*.py
EXPOSE 8000
CMD ["python3", "/srv/app.py"]
