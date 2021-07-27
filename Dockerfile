FROM python:3.8-alpine

LABEL org.opencontainers.image.source https://github.com/onuratakan/HACON

RUN apk update
RUN apk add git

RUN pip3 install --upgrade pip setuptools wheel
RUN pip install HACON

CMD ["HACON -h"]
