#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container-uninstall.sh
# Reverse every change made by cloudflared-container-setup.sh on an
# Alma Linux 9 server running rootless cloudflared via Podman Quadlet.
#
# This script mirrors cloudflared-container-setup.sh step for step and
# reverses only what that script actually does:
#  1) Stop, disable, and remove the cloudflared.service + Quadlet files
#     (base container unit, image/icmp/token drop-ins, token env file)
#  2) Remove the cloudflared container and pulled image(s)
#  3) Disable linger for the cloudflared user
#  4) Remove /etc/sysctl.d/99-cloudflared.conf (ping_group_range, UDP buffers)
#  5) OPTIONAL policy routing rollback (only if it was configured):
#      - remove ip rule for traffic sourced from the eth1 IPv4 address
#      - remove RFC1918 routes from route-table "origin" on eth1
#      - remove the "origin" entry from /etc/iproute2/rt_tables
#      - remove persistence files: /etc/sysconfig/network-scripts/route-eth1
#        and rule-eth1
#      - restore eth1's NetworkManager profile (re-enable default-route
#        eligibility, i.e. undo ipv4.never-default yes / gateway removal)
#  6) Remove /etc/systemd/journald.conf.d/99-persistent.conf (persistent
#     journaling) and restart journald if requested
#  7) Remove /etc/profile.d/cloudflared-aliases.sh
#  8) Remove /usr/local/sbin/cloudflared-container management command
#  9) Remove subuid/subgid ranges this setup allocated for the cloudflared
#     user (only the range the setup script adds: 100000-165535), IF the
#     user account itself is not being kept for other purposes
# 10) OPTIONAL: remove the cloudflared user account and home directory
#
# What this script deliberately does NOT touch:
#  - Packages installed by setup (podman, passt) -- shared system packages,
#    not safe to assume they're unused elsewhere. Removal command is printed
#    at the end for you to run manually if desired.
#  - eth0's default route / gateway -- setup never modifies eth0, so
#    uninstall never touches it either.
#  - Any Cloudflare edge IP allow-list routes -- setup does not create
#    these, so there is nothing to reverse here.
#
# Usage:
#   sudo bash cloudflared-container-uninstall.sh
#------------------------------------------------------------------------------

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*" >&2; }
warn() { echo "WARN: $*" >&2; }

require_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"; }

user_exists() { id "$1" >/dev/null 2>&1; }

user_uid() { id -u "$1"; }

iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }

is_systemctl_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

get_nmcli_con_for_dev() {
  local dev="$1"
  command -v nmcli >/dev/null 2>&1 || return 0
  nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$dev" '$2==d {print $1; exit}'
}

# Run systemctl --user for a given user in non-interactive contexts.
# Mirrors user_systemctl() in the setup script.
user_systemctl() {
  local u="$1"; shift
  local uid; uid="$(user_uid "$u")"
  local runtime_dir="/run/user/${uid}"

  if [[ ! -d "$runtime_dir" ]]; then
    mkdir -p "$runtime_dir"
    chown "${uid}:${uid}" "$runtime_dir"
    chmod 0700 "$runtime_dir"
  fi

  sudo -u "$u" env XDG_RUNTIME_DIR="$runtime_dir" systemctl --user "$@"
}

user_service_exists() {
  local u="$1" service="$2"
  local uid; uid="$(user_uid "$u")"
  local runtime_dir="/run/user/${uid}"

  sudo -u "$u" env XDG_RUNTIME_DIR="$runtime_dir" \
    systemctl --user list-unit-files "$service" 2>/dev/null | grep -q "$service"
}

user_home() {
  local u="$1"
  getent passwd "$u" | awk -F: '{print $6}'
}

#------------------------------------------------------------------------------
# 1) Stop, disable, and remove the cloudflared service + Quadlet files
#------------------------------------------------------------------------------
stop_disable_and_remove_service() {
  local u="$1"

  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping service stop/removal"
    return 0
  fi

  info "Stopping and disabling cloudflared.service for user: $u"

  if user_service_exists "$u" cloudflared.service; then
    user_systemctl "$u" stop cloudflared.service 2>/dev/null || warn "Failed to stop cloudflared.service"
    user_systemctl "$u" disable cloudflared.service 2>/dev/null || warn "Failed to disable cloudflared.service"
  else
    warn "cloudflared.service not found for user $u (may already be removed)"
  fi

  local homedir quadlet_dir
  homedir="$(user_home "$u")"
  if [[ -z "$homedir" || ! -d "$homedir" ]]; then
    warn "Could not determine home directory for user: $u; skipping Quadlet file removal"
    return 0
  fi

  quadlet_dir="${homedir}/.config/containers/systemd"

  if [[ -d "$quadlet_dir" ]]; then
    info "Removing Quadlet files from: $quadlet_dir"
    # Matches exactly what create_quadlet_rootless() in setup writes:
    #   cloudflared.container, cloudflared.container.d/{40-image,50-icmp,50-token}.conf,
    #   cloudflared.container.d/cloudflared.env
    rm -f "${quadlet_dir}/cloudflared.container"
    rm -rf "${quadlet_dir}/cloudflared.container.d"
  else
    warn "Quadlet directory not found: $quadlet_dir (may already be removed)"
  fi

  info "Reloading systemd --user daemon for: $u"
  user_systemctl "$u" daemon-reload 2>/dev/null || warn "Failed to reload user daemon for $u"
  user_systemctl "$u" reset-failed cloudflared.service 2>/dev/null || true
}

#------------------------------------------------------------------------------
# 2) Remove the cloudflared container and pulled image(s)
#------------------------------------------------------------------------------
remove_container_and_image() {
  local u="$1" tag="${2:-}"

  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping container/image removal"
    return 0
  fi

  local homedir
  homedir="$(user_home "$u")"
  if [[ -z "$homedir" || ! -d "$homedir" ]]; then
    warn "Could not determine home directory for user: $u; skipping container/image removal"
    return 0
  fi

  info "Removing cloudflared container for user: $u"
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman rm -f cloudflared" >/dev/null 2>&1 || \
    warn "No running/stopped 'cloudflared' container found (or removal failed)"

  info "Removing pulled cloudflared image(s) for user: $u"
  if [[ -n "$tag" ]]; then
    sudo -H -u "$u" bash -lc "cd '$homedir' && podman rmi -f 'docker.io/cloudflare/cloudflared:${tag}'" >/dev/null 2>&1 || \
      warn "Image docker.io/cloudflare/cloudflared:${tag} not found (or removal failed)"
  else
    sudo -H -u "$u" bash -lc "
      cd '$homedir'
      ids=\$(podman images 'docker.io/cloudflare/cloudflared' -q)
      if [[ -n \"\$ids\" ]]; then
        podman rmi -f \$ids
      fi
    " >/dev/null 2>&1 || warn "No cloudflared images found (or removal failed)"
  fi
}

#------------------------------------------------------------------------------
# 3) Disable linger for the cloudflared user
#------------------------------------------------------------------------------
disable_linger_for_user() {
  local u="$1"

  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping linger disable"
    return 0
  fi

  info "Disabling linger for user: $u"
  loginctl disable-linger "$u" 2>/dev/null || warn "Failed to disable linger for $u (may already be disabled)"
}

#------------------------------------------------------------------------------
# 4) Remove /etc/sysctl.d/99-cloudflared.conf
#------------------------------------------------------------------------------
remove_sysctl_cloudflared() {
  local sysctl_file="/etc/sysctl.d/99-cloudflared.conf"

  if [[ -f "$sysctl_file" ]]; then
    info "Removing sysctl configuration: $sysctl_file"
    rm -f "$sysctl_file"
    sysctl --system >/dev/null 2>&1 || warn "Failed to reload sysctl settings after removal"
  else
    warn "sysctl configuration not found: $sysctl_file (may already be removed)"
  fi
}

#------------------------------------------------------------------------------
# 5) Reverse dual-NIC policy routing (only if it was configured)
#------------------------------------------------------------------------------
remove_policy_routing_two_nic() {
  local eth1_ip="$1"
  local eth1_iface="${2:-eth1}"
  local rt_name="origin"
  local rt_id="100"
  local rt_tables_file="/etc/iproute2/rt_tables"
  local rules_file="/etc/sysconfig/network-scripts/rule-eth1"
  local routes_file="/etc/sysconfig/network-scripts/route-eth1"

  if ! iface_exists "$eth1_iface"; then
    warn "Interface $eth1_iface not found; skipping policy routing rollback"
    return 0
  fi

  info "Reversing policy routing configured on ${eth1_iface}"

  # Remove the ip rule that sends eth1-sourced traffic into the origin table.
  if [[ -n "$eth1_ip" ]]; then
    ip rule del from "${eth1_ip}/32" table "$rt_name" priority 100 2>/dev/null || \
      warn "ip rule for ${eth1_ip}/32 -> table ${rt_name} not found (may already be removed)"
  else
    warn "No eth1 IPv4 address provided; skipping targeted ip rule removal (check 'ip rule show' manually)"
  fi

  # Remove RFC1918 routes from the origin table (mirrors the three
  # ip route replace calls in configure_policy_routing_two_nic()).
  ip route del 10.0.0.0/8 dev "$eth1_iface" table "$rt_name" 2>/dev/null || true
  ip route del 172.16.0.0/12 dev "$eth1_iface" table "$rt_name" 2>/dev/null || true
  ip route del 192.168.0.0/16 dev "$eth1_iface" table "$rt_name" 2>/dev/null || true

  # Remove the named route table entry from rt_tables.
  if [[ -f "$rt_tables_file" ]] && grep -Eq "^[[:space:]]*${rt_id}[[:space:]]+${rt_name}([[:space:]]|$)" "$rt_tables_file"; then
    info "Removing '${rt_id} ${rt_name}' entry from ${rt_tables_file}"
    sed -i.bak -E "/^[[:space:]]*${rt_id}[[:space:]]+${rt_name}([[:space:]]|$)/d" "$rt_tables_file"
    rm -f "${rt_tables_file}.bak"
  else
    warn "'${rt_id} ${rt_name}' entry not found in ${rt_tables_file} (may already be removed)"
  fi

  # Remove persistence files written by setup.
  if [[ -f "$routes_file" ]]; then
    info "Removing route persistence file: $routes_file"
    rm -f "$routes_file"
  else
    warn "Route persistence file not found: $routes_file"
  fi

  if [[ -f "$rules_file" ]]; then
    info "Removing rule persistence file: $rules_file"
    rm -f "$rules_file"
  else
    warn "Rule persistence file not found: $rules_file"
  fi

  # Restore eth1's NetworkManager profile: undo ipv4.never-default yes and
  # the removed ipv4.gateway that configure_policy_routing_two_nic() applied.
  if command -v nmcli >/dev/null 2>&1; then
    local con1
    con1="$(get_nmcli_con_for_dev "$eth1_iface" || true)"
    if [[ -n "$con1" ]]; then
      info "Restoring NetworkManager default-route eligibility for ${eth1_iface}: ${con1}"
      nmcli con mod "$con1" ipv4.never-default no >/dev/null 2>&1 || \
        warn "Failed to reset ipv4.never-default on ${con1}"
      info "Note: eth1's gateway was removed by setup and its original value was not recorded;"
      info "      set it manually if eth1 needs a gateway again: nmcli con mod ${con1} ipv4.gateway <ip>"
      nmcli con up "$con1" >/dev/null 2>&1 || warn "Failed to bring up connection: $con1"
    else
      warn "No active NetworkManager connection found for ${eth1_iface}; skipping profile restore"
    fi
  fi

  info "Policy routing rollback sanity check:"
  ip rule show | sed 's/^/  /'
  ip route show table "$rt_name" 2>/dev/null | sed 's/^/  /' || echo "  (table ${rt_name} is now empty or removed)"
}

#------------------------------------------------------------------------------
# 6) Remove persistent journaling configuration
#------------------------------------------------------------------------------
remove_journaling_config() {
  local journal_conf="/etc/systemd/journald.conf.d/99-persistent.conf"

  if [[ ! -f "$journal_conf" ]]; then
    warn "Journaling configuration not found: $journal_conf (may already be removed)"
    return 0
  fi

  info "Removing persistent journaling configuration: $journal_conf"
  rm -f "$journal_conf"

  read -r -p "Restart systemd-journald now to apply the change? [y/N]: " restart_journal
  if [[ "${restart_journal,,}" == "y" ]]; then
    systemctl restart systemd-journald.service
    info "systemd-journald restarted"
  else
    warn "Journald config removed but service not restarted; change applies after reboot"
  fi
}

#------------------------------------------------------------------------------
# 7) Remove /etc/profile.d/cloudflared-aliases.sh
#------------------------------------------------------------------------------
remove_cloudflared_aliases() {
  local aliases_file="/etc/profile.d/cloudflared-aliases.sh"

  if [[ -f "$aliases_file" ]]; then
    info "Removing shell aliases: $aliases_file"
    rm -f "$aliases_file"
  else
    warn "Aliases file not found: $aliases_file (may already be removed)"
  fi
}

#------------------------------------------------------------------------------
# 8) Remove the /usr/local/sbin/cloudflared-container management command
#    installed by cloudflared-container-setup.sh
#------------------------------------------------------------------------------
remove_management_command() {
  local install_path="/usr/local/sbin/cloudflared-container"

  if [[ -f "$install_path" ]]; then
    info "Removing management command: $install_path"
    rm -f "$install_path"
  else
    warn "Management command not found: $install_path (may already be removed)"
  fi
}

#------------------------------------------------------------------------------
# 9) Remove the subuid/subgid range setup allocated (100000-165535)
#------------------------------------------------------------------------------
remove_subuid_subgid_range() {
  local u="$1"
  local range="100000-165535"

  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping subuid/subgid cleanup"
    return 0
  fi

  info "Removing subuid/subgid range ${range} for user: $u (only if it matches what setup allocated)"

  if command -v usermod >/dev/null 2>&1; then
    usermod --del-subuids "$range" --del-subgids "$range" "$u" 2>/dev/null || \
      warn "usermod could not remove subuid/subgid range for $u (may not match, or already removed)"
  else
    warn "usermod not available; edit /etc/subuid and /etc/subgid manually if needed"
  fi
}

#------------------------------------------------------------------------------
# 10) Optionally remove the cloudflared user account
#------------------------------------------------------------------------------
remove_user_account() {
  local u="$1"

  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping user removal"
    return 0
  fi

  info "Removing user account: $u (including home directory)"
  userdel -r "$u" 2>/dev/null || warn "Failed to fully remove user $u (may have running processes; check 'loginctl' / 'ps')"
}

main() {
  require_root

  echo "=========================================="
  echo "Cloudflared Container Uninstall Script"
  echo "=========================================="
  echo
  echo "This reverses the changes made by cloudflared-container-setup.sh."
  echo

  read -r -p "Enter the username that runs cloudflared [cloudflared]: " CF_USER
  CF_USER="${CF_USER:-cloudflared}"

  if ! user_exists "${CF_USER}"; then
    warn "User ${CF_USER} does not exist. Steps tied to that user will be skipped."
  fi

  read -r -p "Enter the cloudflared image tag to remove (leave blank to remove all cloudflared images): " CF_TAG

  echo
  read -r -p "Was dual-NIC origin policy routing configured on this host? [y/N]: " TWO_NIC_ROUTING
  TWO_NIC_ROUTING="${TWO_NIC_ROUTING,,}"

  ETH1_IFACE="eth1"
  ETH1_IP=""
  if [[ "$TWO_NIC_ROUTING" == "y" ]]; then
    read -r -p "Enter the secondary interface name [eth1]: " ETH1_IFACE
    ETH1_IFACE="${ETH1_IFACE:-eth1}"

    if iface_exists "$ETH1_IFACE"; then
      ETH1_IP="$(ip -4 -o addr show dev "$ETH1_IFACE" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
    fi

    if [[ -z "$ETH1_IP" ]]; then
      read -r -p "Could not auto-detect ${ETH1_IFACE}'s IPv4 address. Enter it manually (or leave blank to skip the ip-rule removal step): " ETH1_IP
    else
      info "Detected ${ETH1_IFACE} IPv4 address: ${ETH1_IP}"
    fi
  fi

  echo
  echo "Starting uninstall..."
  echo

  # 1. Stop, disable, and remove the service + Quadlet files
  stop_disable_and_remove_service "${CF_USER}"

  # 2. Remove container and image(s)
  remove_container_and_image "${CF_USER}" "${CF_TAG}"

  # 3. Disable linger
  disable_linger_for_user "${CF_USER}"

  # 4. Remove sysctl config
  remove_sysctl_cloudflared

  # 5. Reverse policy routing, only if it was configured
  if [[ "$TWO_NIC_ROUTING" == "y" ]]; then
    echo
    remove_policy_routing_two_nic "${ETH1_IP}" "${ETH1_IFACE}"
  else
    info "Skipping policy routing rollback (not configured on this host)"
  fi

  # 6. Remove persistent journaling config
  echo
  read -r -p "Remove persistent journaling configuration? [y/N]: " REMOVE_JOURNAL
  REMOVE_JOURNAL="${REMOVE_JOURNAL,,}"
  if [[ "$REMOVE_JOURNAL" == "y" ]]; then
    remove_journaling_config
  else
    info "Keeping persistent journaling configuration"
  fi

  # 7. Remove shell aliases
  remove_cloudflared_aliases

  # 8. Remove the cloudflared-container management command
  remove_management_command

  # 9/10. subuid/subgid + optional user removal
  echo
  read -r -p "Remove user account '${CF_USER}' and home directory? [y/N]: " REMOVE_USER
  REMOVE_USER="${REMOVE_USER,,}"
  if [[ "$REMOVE_USER" == "y" ]]; then
    # userdel -r deletes the home directory and, on most distros, the
    # associated subuid/subgid entries. Run the explicit removal first
    # in case that behavior differs.
    remove_subuid_subgid_range "${CF_USER}"
    remove_user_account "${CF_USER}"
  else
    info "Keeping user account: ${CF_USER} (leaving subuid/subgid range intact for future rootless use)"
  fi

  echo
  info "=========================================="
  info "Uninstall complete!"
  info "=========================================="
  echo
  info "Summary of what was processed:"
  echo "  - cloudflared.service stopped, disabled, and Quadlet files removed"
  echo "  - Container and image(s) removed"
  echo "  - Linger disabled for ${CF_USER}"
  echo "  - /etc/sysctl.d/99-cloudflared.conf removed"
  if [[ "$TWO_NIC_ROUTING" == "y" ]]; then
    echo "  - Policy routing reversed on ${ETH1_IFACE} (ip rule, origin table routes, rt_tables entry, persistence files, NetworkManager profile)"
  fi
  [[ "$REMOVE_JOURNAL" == "y" ]] && echo "  - Persistent journaling configuration removed"
  echo "  - /etc/profile.d/cloudflared-aliases.sh removed"
  echo "  - /usr/local/sbin/cloudflared-container management command removed"
  if [[ "$REMOVE_USER" == "y" ]]; then
    echo "  - subuid/subgid range removed and user account '${CF_USER}' deleted"
  fi
  echo
  info "Not removed (shared system state, left for you to review):"
  echo "  - Packages: podman, passt -- remove manually if unused elsewhere:"
  echo "      sudo dnf remove podman passt"
  if [[ "$TWO_NIC_ROUTING" == "y" ]]; then
    echo "  - eth1's original NetworkManager gateway value (removed by setup, not recorded) -- set manually if needed:"
    echo "      nmcli con mod <connection> ipv4.gateway <ip>"
  fi
  echo
  info "Verify final state:"
  echo "  ip rule show"
  echo "  ip route show"
  echo "  systemctl status systemd-journald"
  echo
}

main "$@"
