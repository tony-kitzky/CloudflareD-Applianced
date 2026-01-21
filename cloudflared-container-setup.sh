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
#      a) username to run rootless cloudflared (create if missing)
#      b) cloudflared image tag
#      c) cloudflared tunnel token (dashboard-generated)
#      d) whether server uses 1 NIC or 2 NICs (NEW)
#      e) RFC1918 next-hop gateway IP for routes via eth1 (only if 2 NICs)
#  3) Enable persistent journaling + per-user journals
#  4) Enable boot-start for user services (linger) for the cloudflared user
#  5) Write /etc/sysctl.d/99-cloudflared.conf
#  6) OPTIONAL host routes if 2 NICs:
#      - default remains on eth0
#      - RFC1918 prefixes via eth1 next-hop (prompted)
#      - ensure eth1 has NO default route
#      - persistence via NetworkManager if active; otherwise runtime only
#  7) Pull cloudflared image (fully-qualified docker.io/cloudflare/cloudflared:<tag>)
#  8) Create Quadlet base + drop-ins
#  9) Start the cloudflared.service (systemd --user) for the selected user
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

is_systemctl_active() { systemctl is-active --quiet "$1"; }

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

# Run systemctl --user for a given user in non-interactive contexts.
user_systemctl() {
  local u="$1"; shift
  local uid; uid="$(user_uid "$u")"

  mkdir -p "/run/user/${uid}"
  chown "${uid}:${uid}" "/run/user/${uid}"
  chmod 0700 "/run/user/${uid}"

  sudo -u "$u" env XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user "$@"
}

# Get default gateway for eth0 from "ip route show"
get_default_gw_for_dev() {
  local dev="$1"
  ip route show default 2>/dev/null | awk -v d="$dev" '
    $1=="default" {
      via=""; devx="";
      for(i=1;i<=NF;i++){
        if($i=="via") via=$(i+1);
        if($i=="dev") devx=$(i+1);
      }
      if(devx==d && via!=""){print via; exit}
    }'
}

get_nmcli_con_for_dev() {
  local dev="$1"
  command -v nmcli >/dev/null 2>&1 || return 0
  nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$dev" '$2==d {print $1; exit}'
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
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

configure_routes_two_nic() {
  local eth1_rfc1918_gw="$1"

  info "Configuring routes: default via eth0; RFC1918 via eth1 next-hop ${eth1_rfc1918_gw}; ensure eth1 has no default route"

  local eth0_gw
  eth0_gw="$(get_default_gw_for_dev eth0 || true)"
  [[ -n "$eth0_gw" ]] || die "Could not determine eth0 default gateway from: ip route show default"

  # Remove any default route on eth1 at runtime (ignore errors if none exist)
  ip route del default dev eth1 2>/dev/null || true

  # Add/replace RFC1918 routes via eth1 gateway at runtime
  ip route replace 10.0.0.0/8 via "$eth1_rfc1918_gw" dev eth1
  ip route replace 172.16.0.0/12 via "$eth1_rfc1918_gw" dev eth1
  ip route replace 192.168.0.0/16 via "$eth1_rfc1918_gw" dev eth1

  # Persist via NetworkManager if active
  if is_systemctl_active NetworkManager.service && command -v nmcli >/dev/null 2>&1; then
    info "NetworkManager active; persisting RFC1918 routes in the eth1 connection profile"

    local con1 con0
    con0="$(get_nmcli_con_for_dev eth0 || true)"
    con1="$(get_nmcli_con_for_dev eth1 || true)"
    [[ -n "$con1" ]] || die "NetworkManager active but could not find an active NM connection for eth1"

    nmcli con mod "$con1" ipv4.never-default yes || true

    nmcli con mod "$con1" -ipv4.routes "10.0.0.0/8 $eth1_rfc1918_gw" >/dev/null 2>&1 || true
    nmcli con mod "$con1" -ipv4.routes "172.16.0.0/12 $eth1_rfc1918_gw" >/dev/null 2>&1 || true
    nmcli con mod "$con1" -ipv4.routes "192.168.0.0/16 $eth1_rfc1918_gw" >/dev/null 2>&1 || true

    nmcli con mod "$con1" +ipv4.routes "10.0.0.0/8 $eth1_rfc1918_gw"
    nmcli con mod "$con1" +ipv4.routes "172.16.0.0/12 $eth1_rfc1918_gw"
    nmcli con mod "$con1" +ipv4.routes "192.168.0.0/16 $eth1_rfc1918_gw"

    nmcli con up "$con1" >/dev/null
    [[ -n "$con0" ]] && nmcli con up "$con0" >/dev/null || true
  else
    info "NetworkManager not active; routes applied at runtime only (not persistent)."
  fi

  info "Route sanity check:"
  ip route get 10.1.2.3 | sed 's/^/  /'
  ip route get 1.1.1.1 | sed 's/^/  /'
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
  local homedir quadlet_dir container_file dropin_dir image_dropin token_dropin

  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || die "Could not determine home directory for user: $u"

  quadlet_dir="${homedir}/.config/containers/systemd"
  container_file="${quadlet_dir}/cloudflared.container"
  dropin_dir="${quadlet_dir}/cloudflared.container.d"
  image_dropin="${dropin_dir}/40-image.conf"
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

  # Validate primary NIC presence early
  iface_exists eth0 || die "Interface eth0 not found. This script expects eth0 as the primary NIC."

  install_packages

  echo
  read -r -p "Enter username to run cloudflared (rootless) [will be created if missing]: " CF_USER
  [[ -n "${CF_USER}" ]] || die "Username cannot be empty"
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

  ETH1_RFC1918_GW=""
  if [[ "${NIC_COUNT}" == "2" ]]; then
    iface_exists eth1 || die "You selected 2 NICs, but interface eth1 was not found."

    echo
    read -r -p "Enter RFC1918 next-hop gateway IP to use via eth1 (e.g., 10.98.0.1): " ETH1_RFC1918_GW
    is_ipv4 "${ETH1_RFC1918_GW}" || die "Invalid IPv4 address for RFC1918 next-hop gateway: ${ETH1_RFC1918_GW}"
  else
    info "Single-NIC selected; skipping RFC1918 static route configuration."
  fi

  enable_persistent_journaling
  enable_linger_for_user "${CF_USER}"
  write_sysctl_cloudflared

  if [[ "${NIC_COUNT}" == "2" ]]; then
    configure_routes_two_nic "${ETH1_RFC1918_GW}"
  fi

  pull_cloudflared_image_rootless "${CF_USER}" "${CF_TAG}"
  create_quadlet_rootless "${CF_USER}" "${CF_TAG}" "${CF_TOKEN}"

  info "Done. Verify after reboot:"
  echo "  sudo -u ${CF_USER} env XDG_RUNTIME_DIR=/run/user/\$(id -u ${CF_USER}) systemctl --user status cloudflared.service -l --no-pager"
  echo "  journalctl --user -u cloudflared.service -b --no-pager | tail -n 200"
}

main "$@"
