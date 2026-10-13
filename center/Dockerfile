FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml alembic.ini ./
COPY app ./app
COPY scripts ./scripts
RUN pip install --upgrade pip && pip install .

COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Offline GeoIP/ASN dataset (public domain, iptoasn.com). Non-fatal if the
# download is unavailable — the center degrades to no enrichment.
RUN mkdir -p /geodata && python -c "import urllib.request; urllib.request.urlretrieve('https://iptoasn.com/data/ip2asn-v4.tsv.gz','/geodata/ip2asn-v4.tsv.gz')" || echo "geoip dataset download skipped"

EXPOSE 8000

ENTRYPOINT ["sh", "entrypoint.sh"]
