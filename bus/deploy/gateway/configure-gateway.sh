#!/usr/bin/env bash
# Configure the Strugglebus satellite gateway. Run as root on the gateway
# through a channel that needs no open management port, such as `pct exec`
# on its Proxmox host.
#
#   configure-gateway.sh init
#       Install WireGuard and nftables, mask Debian's nftables.service, enable
#       forwarding from this script's own sysctl file, and generate the
#       gateway's tunnel key once. Prints the gateway public key.
#   configure-gateway.sh peer BUS_PUBLIC_KEY BUS_TUNNEL_IP GATEWAY_TUNNEL_CIDR BUS_SOURCE_IP
#       The values may instead be named, as BUS_PUBLIC_KEY=... and so on.
#       BUS_SOURCE_IP is the address the bus's WireGuard packets arrive from.
#       Admit the bus as the only peer and forward public TCP 443, unopened,
#       to the bus's satellite proxy on 8443. The bus's LAN Caddy holds 443
#       on every interface, so the tunnel must never deliver to 443.
#
# The gateway is TLS-keyless: it holds only its WireGuard key and never sees
# satellite traffic in the clear. It replaces only its own nftables table,
# and the tunnel comes up only once that table has loaded.
set -euo pipefail

SYSCTL_FILE=/etc/sysctl.d/90-strugglebus-gateway.conf
NFT_FILE=/etc/wireguard/strugglebus-gateway.nft

die() {
  printf 'configure-gateway: %s\n' "$1" >&2
  exit 1
}

is_ipv4() {
  printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

require_forwarding() {
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ] || die "net.ipv4.ip_forward is not 1"
}

init() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update >/dev/null
  apt-get -qq install -y wireguard-tools nftables >/dev/null
  # Debian's nftables.service flushes every table whenever it starts or is
  # restarted by an upgrade, including this script's; it must never run here.
  systemctl mask -q nftables.service
  printf 'net.ipv4.ip_forward = 1\n' > "$SYSCTL_FILE"
  # Only this file: a container may refuse unrelated system-wide settings.
  sysctl -q -p "$SYSCTL_FILE"
  require_forwarding
  umask 077
  mkdir -p /etc/wireguard
  [ -s /etc/wireguard/private.key ] || wg genkey > /etc/wireguard/private.key
  printf 'gateway_public_key=%s\n' "$(wg pubkey < /etc/wireguard/private.key)"
}

peer() {
  if [ "$#" -eq 0 ]; then
    set -- "${BUS_PUBLIC_KEY:-}" "${BUS_TUNNEL_IP:-}" "${GATEWAY_TUNNEL_CIDR:-}" "${BUS_SOURCE_IP:-}"
  fi
  [ "$#" -eq 4 ] || die "usage: peer BUS_PUBLIC_KEY BUS_TUNNEL_IP GATEWAY_TUNNEL_CIDR BUS_SOURCE_IP"
  local bus_key=$1 bus_ip=$2 gateway_cidr=$3 bus_source=$4
  printf '%s' "$bus_key" | grep -Eq '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$' || die "invalid bus public key"
  is_ipv4 "$bus_ip" || die "invalid bus tunnel address"
  printf '%s' "$gateway_cidr" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/(2[4-9]|3[0-2])$' || die "invalid gateway tunnel CIDR"
  is_ipv4 "$bus_source" || die "invalid bus source address"
  [ -s /etc/wireguard/private.key ] || die "run init first"
  require_forwarding
  local nic
  nic=$(ip -o route show default | awk '{print $5; exit}')
  [ -n "$nic" ] || die "no default route"

  umask 077
  cat > "$NFT_FILE.new" <<NFT
#!/usr/sbin/nft -f
# Managed by configure-gateway.sh. Replaces only this table.
table inet strugglebus_gateway {}
delete table inet strugglebus_gateway
table inet strugglebus_gateway {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    ct state established,related accept
    iifname "$nic" ip saddr $bus_source udp dport 51820 accept
  }
  chain prerouting {
    type nat hook prerouting priority dstnat;
    iifname "$nic" tcp dport 443 dnat ip to $bus_ip:8443
  }
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "wg0" masquerade
  }
  # Real client addresses exist only here: past the masquerade every client
  # is the gateway, so this is the one place one source can be held back.
  set new_by_source {
    type ipv4_addr; size 65535; flags dynamic; timeout 1m;
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname "$nic" oifname "wg0" ip daddr $bus_ip tcp dport 8443 ct status dnat ct state new add @new_by_source { ip saddr limit rate over 10/second burst 20 packets } drop
    iifname "$nic" oifname "wg0" ip daddr $bus_ip tcp dport 8443 ct status dnat accept
  }
}
NFT
  nft -c -f "$NFT_FILE.new" || die "firewall candidate is invalid"
  mv "$NFT_FILE.new" "$NFT_FILE"
  nft -f "$NFT_FILE"

  # PreUp reloads the table at every start, so the tunnel never comes up
  # without it.
  cat > /etc/wireguard/wg0.conf <<WG
[Interface]
Address = $gateway_cidr
ListenPort = 51820
PreUp = nft -f $NFT_FILE
PostUp = wg set %i private-key /etc/wireguard/private.key

[Peer]
PublicKey = $bus_key
AllowedIPs = $bus_ip/32
WG
  systemctl enable -q wg-quick@wg0
  systemctl restart wg-quick@wg0
  printf 'peer configured; latest handshake: %s\n' "$(wg show wg0 latest-handshakes | awk '{print $2}')"
}

case "${1:-}" in
  init) init ;;
  peer) shift; peer "$@" ;;
  *) die "usage: configure-gateway.sh init | peer BUS_PUBLIC_KEY BUS_TUNNEL_IP GATEWAY_TUNNEL_CIDR BUS_SOURCE_IP" ;;
esac
