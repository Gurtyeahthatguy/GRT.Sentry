#!/usr/bin/env bash
#
# Creates the nftables table GRT Sentry adds blocked addresses to.
#
#   sudo ./scripts/setup-nftables.sh
#
# It is an ordinary table with two empty sets and a rule that drops traffic to
# whatever is in them. Blocking an address adds one element to a set; no rule
# is ever written by the program.
#
# To see what is blocked:  sudo nft list table inet grtsentry
# To unblock one address:  sudo nft delete element inet grtsentry blacklist '{ 1.2.3.4 }'
# To remove all of it:     sudo nft delete table inet grtsentry
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "This has to run as root: sudo $0" >&2
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "nft is not installed. On Debian and Ubuntu: apt install nftables" >&2
  exit 1
fi

echo "Creating the inet grtsentry table…"

# Idempotent: 'add' on something that exists is not an error in nftables.
nft add table inet grtsentry

# Two sets, because an IPv4 set cannot hold an IPv6 address.
nft add set inet grtsentry blacklist  '{ type ipv4_addr; flags interval; comment "addresses blocked from GRT Sentry"; }'
nft add set inet grtsentry blacklist6 '{ type ipv6_addr; flags interval; comment "addresses blocked from GRT Sentry"; }'

# The output hook stops this machine reaching the address. It is not an
# inbound firewall.
nft add chain inet grtsentry output '{ type filter hook output priority 0; policy accept; }'

# Added only if not already there, since 'add rule' would append a duplicate.
if ! nft list chain inet grtsentry output | grep -q '@blacklist '; then
  nft add rule inet grtsentry output ip daddr @blacklist drop
fi
if ! nft list chain inet grtsentry output | grep -q '@blacklist6'; then
  nft add rule inet grtsentry output ip6 daddr @blacklist6 drop
fi

echo
nft list table inet grtsentry
echo
echo "Done. The sets are empty until you block something from the interface."
echo
echo "nftables rules do not survive a reboot on their own. To keep them, save"
echo "the ruleset the way the distribution expects. On Debian and Ubuntu:"
echo
echo "    sudo nft list ruleset > /etc/nftables.conf"
echo "    sudo systemctl enable nftables"
