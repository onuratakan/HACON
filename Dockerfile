FROM python:3.8

LABEL org.opencontainers.image.source https://github.com/onuratakan/HACON

RUN pip install HACON

CMD ["HACON -h"]
