#!/bin/sh
set -e

echo "Starting async-snmp test container"
echo "SNMPv2c communities: public (ro), private (rw)"
echo "SNMPv3 users: noauth_*, authmd5_*, authsha*_*, priv*_*"

# Run snmpd in foreground with logging to stdout
# Note: Don't use -C as it prevents loading /var/lib/net-snmp/snmpd.conf (user credentials)
# Use agentAddress in config instead of command line for flexibility
exec /usr/sbin/snmpd -f -Lo
