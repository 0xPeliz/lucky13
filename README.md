<!-- Sostituisci i campi tra parentesi quadre con le informazioni del progetto. -->

# Lucky13 (CVE-2013-0169) Exploit


This project provides a proof-of-concept exploit to test and verify the CVE-2013-0169 vulnerability (commonly known as Lucky13) in real-world scenarios. 

## 🎓Academic Project
 It was developed as part of a Bachelor's Degree thesis (Tesi di Laurea Triennale) at the Faculty of Computer Systems and Networks Security, University of Milan, to analyze and reproduce Lucky13 vulnerabilty. 


## ⚠️ Disclaimer

**This project is created exclusively for educational and security research purpose. Do not use this tool on systems for which you don't have explicit permission. The author is not responsable for any misuse.**


## 📖 Background
Lucky 13 was published by AlFardan and Paterson in 2013. It exploits small timing differences in how TLS/DTLS implementations process CBC-padded records.
This repository reproduces the attack against OpenSSL 1.0.1c, which predates the fix. 


## 📂 Project Structure

```
├── attacker/           # Contains all the proxy source files and headers
├── client.c            # Client that simulates a browser with a malware
├── newclient.c         # Modified client just for particular testing
├── server.c            # Server implementation
├── new_server.c        # Modified server just for particular testing
├── openssl-1.0.1c/     # Vulnerable OpenSSL used as the target
├── config/             # Contains all the files for Docker Network testing
├── stats/              # Contains statistical analysis tools
├── script.py           # Just to generate the cookie for the client
├── build.sh            # Generates the certificates needed for localhost testing
└── build-outside.sh    # Generates the certificates needed for LAN testing
```

## 📑 Table of contents

- [Features](#features)
- [Dependencies](#dependencies)
- [How to use](#how-to-use)
- [License](#license)

## ✨ Features

- Self-contained lab setup: client, server and attacker components
- Attacker acts as a proxy between a simulated browser and the TLS server
- Runs against a bundled, vulnerable OpenSSL 1.0.1c

## 📦 Dependencies

- Linux based operating system
- gcc, build-essentials, make
- libpcap, libnetfilter_queue
- Python 3 with development headers, `numpy`, `matplotlib`
- Docker
- Root privilege on the host that executes proxy


## 🚀 How to use

#### 1. Clone the repo and go inside the cloned directory
```bash
    git clone https://github.com/0xPeliz/lucky13.git
    cd lucky13
```

#### 2. Compiling the actors
##### Client
```bash
    gcc client.c -o client -lssl -lcrypto
```

##### Proxy
```bash
    cd attacker/src
    gcc -Iinclude -c utility.c -o utility.o
    gcc -IInclude -c network.c -o network.o
    gcc -Iinclude -c proxy.c -o proxy.o
    gcc -I../../stats $(python3-config --cflags --embed) -c ../../stats/stats.c -o ../../stats/stats.o
    gcc proxy.o network.o utility.o ../../stats/stats.o -o proxy -lssl -lcrypto -lnetfilter_queue -lpcap -lpthread $(python3-config --ldflags --embed)
```

##### Server
```bash
    gcc server.c -o server -I/absolute/path/openssl-1.0.1c/include -L/absolute/path/openssl-1.0.1c -lssl -lcrypto -ldl -lpthread
```


#### 3.  Starting the server
```bash
    LD_LIBRARY_PATH=/absolute/path/openssl-1.0.1c taskset -c 0 ./server
```

#### 4. Starting the proxy
```bash
    cd attacker/src
    sudo taskset -c 1 ./proxy -a -op_mode
```
###### op_mode:
- '-l': test in LAN with proxy and client on the same host anche proxy on another host
- '-m': test on the Localhost
- '-n': test in LAN with proxy, client and server on different hosts

#### 5. **Starting the client**
```bash
    taskset -c 2 ./client server_ip server_port
```


## 📜 License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.

The bundled OpenSSL 1.0.1c in `openssl-1.0.1c/` is distributed under its own
license (see `openssl-1.0.1c/LICENSE`).

