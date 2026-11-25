FROM python:3.11-slim
WORKDIR /app
COPY public_site.py report.html chart.umd.min.js /app/
EXPOSE 8000
CMD ["python3", "/app/public_site.py"]
