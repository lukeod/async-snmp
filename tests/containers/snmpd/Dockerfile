FROM debian:trixie-slim

# Install snmpd from distro (includes AES-192/256 support since 5.9.1+dfsg-1)
# See: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=972985
RUN apt-get update && apt-get install -y --no-install-recommends \
    snmpd \
    snmp \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY snmpd.conf /etc/snmp/snmpd.conf
# Debian snmpd uses /var/lib/snmp/ for persistent storage (createUser directives)
COPY snmpd.users.conf /var/lib/snmp/snmpd.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 161/udp

ENTRYPOINT ["/entrypoint.sh"]
