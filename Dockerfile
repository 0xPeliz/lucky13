FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lucky13_attack

RUN wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1c.tar.gz && tar -xzf openssl-1.0.1c.tar.gz

WORKDIR /lucky13_attack/openssl-1.0.1c

RUN ./config shared --prefix=/usr/local/ssl --openssldir=/usr/local/ssl && \
    make clean && \
    make && \
    make install_sw

WORKDIR /lucky13_attack

COPY server.key server.crt ./

COPY server.c .

RUN gcc -O0 server.c -o server_vulnerabile \
    -I/usr/local/ssl/include \
    -L/usr/local/ssl/lib \
    -lssl -lcrypto \
    -Wl,-rpath=/usr/local/ssl/lib

EXPOSE 5000

CMD ["./server_vulnerabile"]
