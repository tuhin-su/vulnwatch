FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt 
RUN groupadd --system app
RUN useradd --system --gid app --no-create-home app
RUN mkdir -p /data 
RUN chown app /data

COPY --chown=app app.py /app/app.py
COPY --chown=app src/ /app/src/
USER app
VOLUME ["/data"]
ENTRYPOINT ["python", "-u", "/app/app.py"]