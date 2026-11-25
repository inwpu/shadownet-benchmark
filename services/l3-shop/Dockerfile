FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 \
    && useradd --uid 10002 --create-home --shell /usr/sbin/nologin appuser
COPY services/l3-shop/shared /app/shared
COPY services/l3-shop/app.py /app/app.py
ENV PYTHONPATH=/app TRACE_FILE=/app/shared/traces.json
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 5000
CMD ["python3", "/app/app.py"]
