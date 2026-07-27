#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container-setup.sh
# Setup environment on Alma Linux 9 server to run rootless container for
#  CloudflareD tunnel daemon.
#
# Vibe coded with ChatGPT 5.2 Thinking LLM on January 20, 2026.
#   -- https://chatgpt.com/share/e/6965778b-c898-8001-b27d-209c0a5024f7
#
# Implements:
#  1) Install packages: podman, passt
#  2) Prompt for:
#      a) username to run rootless cloudflared (create if missing) -- default: cloudflared
#      b) cloudflared image tag
#      c) cloudflared tunnel token (dashboard-generated)
#      d) whether server uses 1 NIC or 2 NICs
#      e) OPTIONAL: enable policy routing for dual-NIC origin traffic via eth1
#  3) Enable persistent journaling + per-user journals
#  4) Enable boot-start for user services (linger) for the cloudflared user
#  5) Write /etc/sysctl.d/99-cloudflared.conf to update system limits for ping users and udp socket buffers
#  6) OPTIONAL policy routing if 2 NICs and enabled:
#      - default remains on eth0
#      - route-table "origin" created in /etc/iproute2/rt_tables
#      - RFC1918 prefixes via eth1 in route-table origin
#      - rule to lookup traffic sourced from the eth1 IPv4 address
#      - persistence via /etc/sysconfig/network-scripts/route-eth1 and rule-eth1
#  7) Pull cloudflared image (fully-qualified docker.io/cloudflare/cloudflared:<tag>)
#  8) Create Quadlet base + drop-ins
#  9) Start the cloudflared.service (systemd --user) for the selected user
# 10) Write /etc/profile.d/cloudflare-alias.sh
#
# Notes:
#  - Token is stored on disk in a drop-in file (0600). Protect the user account.
#  - Rootless systemd user services require a working user runtime dir; the script
#    sets XDG_RUNTIME_DIR to avoid "Failed to connect to bus: No medium found".
#
# Usage:
#   sudo bash cloudflared-container-setup.sh
#------------------------------------------------------------------------------

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"; }

iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }

user_exists() { id "$1" >/dev/null 2>&1; }

ensure_user() {
  local u="$1"
  if user_exists "$u"; then
    info "User exists: $u"
    return 0
  fi
  info "User does not exist, creating: $u"
  useradd -m -s /bin/bash "$u"
}

user_uid() { id -u "$1"; }

get_ipv4_addr_for_dev() {
  local dev="$1"
  ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

# Run systemctl --user for a given user in non-interactive contexts.
user_systemctl() {
  local u="$1"; shift
  local uid; uid="$(user_uid "$u")"

  mkdir -p "/run/user/${uid}"
  chown "${uid}:${uid}" "/run/user/${uid}"
  chmod 0700 "/run/user/${uid}"

  sudo -u "$u" env XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user "$@"
}

install_packages() {
  info "Installing packages: podman, passt"
  dnf install -y podman passt >/dev/null
}

enable_persistent_journaling() {
  info "Enabling persistent journaling and per-user journals (SplitMode=uid)"

  mkdir -p /var/log/journal
  chmod 2755 /var/log/journal

  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/99-persistent.conf <<'EOF'
[Journal]
Storage=persistent
SplitMode=uid
EOF

  systemctl restart systemd-journald.service
  journalctl --flush >/dev/null 2>&1 || true
}

enable_linger_for_user() {
  local u="$1"
  info "Enabling linger (boot-start for systemd --user) for user: $u"
  loginctl enable-linger "$u"
}

write_sysctl_cloudflared() {
  info "Writing /etc/sysctl.d/99-cloudflared.conf"

  cat >/etc/sysctl.d/99-cloudflared.conf <<'EOF'
# Cloudflared ICMP proxy enablement and QUIC UDP socket buffer ceilings.

# Allow the cloudflared container's nonroot group (65532) to create ICMP echo sockets.
net.ipv4.ping_group_range = 0 65532
net.ipv6.ping_group_range = 0 65532

# QUIC UDP socket buffer ceilings (helps avoid quic-go UDP buffer warnings).
net.core.rmem_max = 8000000
net.core.wmem_max = 8000000
EOF

  sysctl --system >/dev/null
}

configure_policy_routing_two_nic() {
  local eth1_ip="$1"
  local rt_name="origin"
  local rt_id="100"
  local rt_tables_file="/etc/iproute2/rt_tables"
  local rules_file="/etc/sysconfig/network-scripts/rule-eth1"
  local routes_file="/etc/sysconfig/network-scripts/route-eth1"

  info "Configuring policy routing for dual-NIC host using route table '${rt_name}' from source ${eth1_ip}"

  if command -v nmcli >/dev/null 2>&1; then
    local con1
    con1="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: '$2=="eth1" {print $1; exit}')"
    if [[ -n "$con1" ]]; then
      info "Removing IPv4 gateway from NetworkManager profile for eth1: ${con1}"
      nmcli con mod "$con1" ipv4.never-default yes >/dev/null 2>&1 || true
      nmcli con mod "$con1" -ipv4.gateway >/dev/null 2>&1 || true
    fi
  fi

  grep -Eq "^[[:space:]]*${rt_id}[[:space:]]+${rt_name}(\\s|$)" "$rt_tables_file" 2>/dev/null || \
    echo "${rt_id} ${rt_name}" >> "$rt_tables_file"



  ip route replace 10.0.0.0/8 dev eth1 table "$rt_name"
  ip route replace 172.16.0.0/12 dev eth1 table "$rt_name"
  ip route replace 192.168.0.0/16 dev eth1 table "$rt_name"

  ip rule del from "$eth1_ip/32" table "$rt_name" 2>/dev/null || true
  ip rule add from "$eth1_ip/32" table "$rt_name" priority 100

  mkdir -p /etc/sysconfig/network-scripts
  cat >"$routes_file" <<EOF
10.0.0.0/8 dev eth1 table ${rt_name}
172.16.0.0/12 dev eth1 table ${rt_name}
192.168.0.0/16 dev eth1 table ${rt_name}
EOF

  cat >"$rules_file" <<EOF
from ${eth1_ip}/32 table ${rt_name} priority 100
EOF

  info "Policy routing sanity check:"
  ip rule show | sed 's/^/  /'
  ip route show table "$rt_name" | sed 's/^/  /'
  ip route get 10.1.2.3 from "$eth1_ip" | sed 's/^/  /' || true
}

pull_cloudflared_image_rootless() {
  local u="$1" tag="$2"
  local homedir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  info "Pulling image as rootless user $u: docker.io/cloudflare/cloudflared:${tag}"
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman pull 'docker.io/cloudflare/cloudflared:${tag}'"
}

create_quadlet_rootless() {
  local u="$1" tag="$2" token="$3"
  local homedir quadlet_dir container_file dropin_dir image_dropin icmp_dropin token_dropin

  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  quadlet_dir="${homedir}/.config/containers/systemd"
  container_file="${quadlet_dir}/cloudflared.container"
  dropin_dir="${quadlet_dir}/cloudflared.container.d"
  image_dropin="${dropin_dir}/40-image.conf"
  icmp_dropin="${dropin_dir}/50-icmp.conf"
  token_dropin="${dropin_dir}/50-token.conf"

  info "Creating Quadlet files for user $u"

  install -d -m 0700 -o "$u" -g "$u" "$quadlet_dir"
  install -d -m 0700 -o "$u" -g "$u" "$dropin_dir"

  cat >"$container_file" <<'EOF'
[Unit]
Description=CloudflareD Tunnel Agent (cloudflared) Container
Wants=network-online.target
After=network-online.target

[Container]
ContainerName=cloudflared
Exec=tunnel --no-autoupdate run

[Service]
Restart=always
TimeoutStartSec=900

[Install]
WantedBy=default.target
EOF
  chown "$u:$u" "$container_file"
  chmod 0600 "$container_file"

  cat >"$image_dropin" <<EOF
[Container]
Image=docker.io/cloudflare/cloudflared:${tag}
Pull=never
EOF
  chown "$u:$u" "$image_dropin"
  chmod 0600 "$image_dropin"

  cat >"$icmp_dropin" <<EOF
[Container]
Sysctl="net.ipv4.ping_group_range=65532 65532"
EOF
  chown "$u:$u" "$icmp_dropin"
  chmod 0600 "$icmp_dropin"

  cat >"$token_dropin" <<EOF
[Container]
Exec=tunnel --no-autoupdate run --token ${token}

[Service]
LimitNOFILE=250000
EOF
  chown "$u:$u" "$token_dropin"
  chmod 0600 "$token_dropin"

  info "Reloading generator and starting service as user $u"
  user_systemctl "$u" daemon-reload
  user_systemctl "$u" reset-failed cloudflared.service || true
  user_systemctl "$u" start cloudflared.service
  user_systemctl "$u" status cloudflared.service -l --no-pager || true
}

main() {
  require_root

  iface_exists eth0 || die "Interface eth0 not found. This script expects eth0 as the primary NIC."

  install_packages

  echo
  read -r -p "Enter username to run cloudflared (rootless) [cloudflared]: " CF_USER
  CF_USER="${CF_USER:-cloudflared}"
  ensure_user "${CF_USER}"

  read -r -p "Enter cloudflared image tag (e.g., 2025.11.1): " CF_TAG
  [[ -n "${CF_TAG}" ]] || die "Image tag cannot be empty"

  echo
  read -r -s -p "Enter Cloudflare tunnel token (dashboard-generated): " CF_TOKEN
  echo
  [[ -n "${CF_TOKEN}" ]] || die "Tunnel token cannot be empty"

  echo
  read -r -p "Does this server have 1 or 2 network interfaces for routing? [1/2]: " NIC_COUNT
  [[ "${NIC_COUNT}" == "1" || "${NIC_COUNT}" == "2" ]] || die "Enter 1 or 2"

  APPLY_POLICY_ROUTING="n"
  ETH1_IP=""

  if [[ "${NIC_COUNT}" == "2" ]]; then
    iface_exists eth1 || die "You selected 2 NICs, but interface eth1 was not found."

    echo
    read -r -p "Configure origin policy routing for cloudflared using eth1? [y/N]: " APPLY_POLICY_ROUTING
    APPLY_POLICY_ROUTING="${APPLY_POLICY_ROUTING:-n}"

    if [[ "${APPLY_POLICY_ROUTING}" =~ ^[Yy]$ ]]; then
      ETH1_IP="$(get_ipv4_addr_for_dev eth1 || true)"
      [[ -n "${ETH1_IP}" ]] || die "Could not determine IPv4 address for eth1. Configure eth1 with an IPv4 address before enabling origin policy routing."
      info "Detected eth1 IPv4 address: ${ETH1_IP}"
    else
      info "Skipping origin policy routing as requested."
    fi
  else
    info "Single-NIC selected; skipping origin route-table configuration."
  fi

  enable_persistent_journaling
  enable_linger_for_user "${CF_USER}"
  write_sysctl_cloudflared

  if [[ "${NIC_COUNT}" == "2" && "${APPLY_POLICY_ROUTING}" =~ ^[Yy]$ ]]; then
    configure_policy_routing_two_nic "${ETH1_IP}"
  fi

  pull_cloudflared_image_rootless "${CF_USER}" "${CF_TAG}"
  create_quadlet_rootless "${CF_USER}" "${CF_TAG}" "${CF_TOKEN}"

  info "Installing cloudflared aliases for user ${CF_USER}"

  cat >/etc/profile.d/cloudflared-aliases.sh <<EOF
alias cloudflared-status='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user status cloudflared.service'
alias cloudflared-stop='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user stop cloudflared.service'
alias cloudflared-start='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user start cloudflared.service'
alias cloudflared-restart='sudo -u ${CF_USER} XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user restart cloudflared.service'
EOF

  chmod 0644 /etc/profile.d/cloudflared-aliases.sh

  info "Done. Verify after reboot:"
  echo "  sudo -u ${CF_USER} env XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user status cloudflared.service -l --no-pager"
  echo "  journalctl --user -u cloudflared.service -b --no-pager | tail -n 200"
  if [[ "${NIC_COUNT}" == "2" && "${APPLY_POLICY_ROUTING}" =~ ^[Yy]$ ]]; then
    echo "  ip rule show"
    echo "  ip route show table origin"
  fi
}

main "$@"
