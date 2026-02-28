FROM debian:sid-slim

# Instal·lem ca-certificates primer per intentar arreglar el problema de SSL
# I fem que apt ignori les validacions de seguretat pel snapshot
RUN apt-get update && apt-get install -y ca-certificates --no-install-recommends

RUN echo "deb [trusted=yes] http://snapshot.debian.org/archive/debian/20240328T025657Z/ sid main" > /etc/apt/sources.list

# Fem l'update usant HTTP en lloc de HTTPS per evitar el drama del certificat
# i li diem que ignori que el snapshot és "antic"
RUN apt-get update -o Acquire::Check-Valid-Until=false

# Instal·lem les versions específiques
RUN apt-get install -y --allow-downgrades --allow-unauthenticated \
    liblzma5=5.6.1-1 \
    xz-utils=5.6.1-1 \
    openssh-server \
    procps \
    gdb \
    strace \
    lsof \
    net-tools \
    iputils-ping \
    curl \
    vim \
    less \
    strings \
    systemd

# Creem el directori necessari per a SSH
RUN mkdir -p /var/run/sshd

# Generem les claus de l'host perquè SSH pugui arrencar
RUN ssh-keygen -A

# Indiquem que el contenidor s'iniciï amb l'init de systemd
CMD ["/lib/systemd/systemd"]