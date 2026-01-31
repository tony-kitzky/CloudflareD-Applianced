#!/usr/bin/env bash
#------------------------------------------------------------------------------
# cloudflared-container-uninstall.sh
# Uninstall the cloudflared rootless container setup on Alma Linux 9 server
#
# This script reverses the changes made by cloudflared-container-setup.sh:
#  1) Stop and disable the cloudflared service
#  2) Remove Quadlet configuration files
#  3) Remove the cloudflared container and image
#  4) Disable user linger
#  5) Remove sysctl configuration
#  6) Remove Cloudflare IPv4 prefix routes
#  7) Remove RFC1918 static routes (if 2 NIC setup was used)
#  8) Restore default route to eth0 interface
#  9) Remove persistent journaling configuration
# 10) Optionally remove the cloudflared user account
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

is_systemctl_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}

get_nmcli_con_for_dev() {
  local dev="$1"
  command -v nmcli >/dev/null 2>&1 || return 0
  nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v d="$dev" '$2==d {print $1; exit}'
}

# Run systemctl --user for a given user
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

# Check if service exists for user
user_service_exists() {
  local u="$1" service="$2"
  local uid; uid="$(user_uid "$u")"
  local runtime_dir="/run/user/${uid}"

  sudo -u "$u" env XDG_RUNTIME_DIR="$runtime_dir" \
    systemctl --user list-unit-files "$service" 2>/dev/null | grep -q "$service" || return 1
}

download_cloudflare_ipv4_prefixes() {
  local cf_url="https://www.cloudflare.com/ips-v4/"
  local temp_file
  temp_file=$(mktemp)
  
  info "Downloading current Cloudflare IPv4 prefixes from: ${cf_url}"
  
  # Try curl first, fall back to wget
  if command -v curl >/dev/null 2>&1; then
    if ! curl -sf -o "$temp_file" "$cf_url" 2>/dev/null; then
      rm -f "$temp_file"
      warn "Failed to download Cloudflare IPv4 prefixes using curl"
      return 1
    fi
  elif command -v wget >/dev/null 2>&1; then
    if ! wget -q -O "$temp_file" "$cf_url" 2>/dev/null; then
      rm -f "$temp_file"
      warn "Failed to download Cloudflare IPv4 prefixes using wget"
      return 1
    fi
  else
    rm -f "$temp_file"
    warn "Neither curl nor wget found. Cannot download Cloudflare prefixes."
    return 1
  fi
  
  # Validate the file contains valid CIDR prefixes
  local prefix_count
  prefix_count=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$temp_file" || echo "0")
  
  if [[ "$prefix_count" -eq 0 ]]; then
    rm -f "$temp_file"
    warn "Downloaded file does not contain valid IPv4 prefixes"
    return 1
  fi
  
  info "Successfully downloaded ${prefix_count} Cloudflare IPv4 prefixes"
  echo "$temp_file"
}

read_cloudflare_prefixes_from_file() {
  local file="$1"
  local -a prefixes=()
  
  while IFS= read -r line; do
    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # Validate CIDR format
    if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+ ]]; then
      prefixes+=("$line")
    fi
  done < "$file"
  
  printf '%s\n' "${prefixes[@]}"
}

stop_and_disable_service() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping service stop"
    return 0
  fi

  info "Stopping and disabling cloudflared service for user: $u"
  
  if user_service_exists "$u" cloudflared.service; then
    user_systemctl "$u" stop cloudflared.service 2>/dev/null || warn "Failed to stop cloudflared.service"
    user_systemctl "$u" disable cloudflared.service 2>/dev/null || warn "Failed to disable cloudflared.service"
  else
    warn "cloudflared.service not found for user $u"
  fi
}

remove_container_and_image() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping container removal"
    return 0
  fi

  local homedir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || { warn "Could not determine home directory for user: $u"; return 0; }

  info "Removing cloudflared container and images for user: $u"
  
  # Remove container
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman rm -f cloudflared 2>/dev/null || true"
  
  # Remove all cloudflared images
  sudo -H -u "$u" bash -lc "cd '$homedir' && podman rmi -f \$(podman images 'docker.io/cloudflare/cloudflared' -q) 2>/dev/null || true"
  
  info "Container and images removed"
}

remove_quadlet_files() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping Quadlet file removal"
    return 0
  fi

  local homedir quadlet_dir
  homedir="$(getent passwd "$u" | awk -F: '{print $6}')"
  [[ -n "$homedir" && -d "$homedir" ]] || { warn "Could not determine home directory for user: $u"; return 0; }

  quadlet_dir="${homedir}/.config/containers/systemd"

  if [[ -d "$quadlet_dir" ]]; then
    info "Removing Quadlet configuration files from: $quadlet_dir"
    rm -rf "${quadlet_dir}/cloudflared.container" \
           "${quadlet_dir}/cloudflared.container.d" 2>/dev/null || true
    
    # Reload daemon to remove generated service files
    user_systemctl "$u" daemon-reload 2>/dev/null || warn "Failed to reload user daemon"
  else
    warn "Quadlet directory not found: $quadlet_dir"
  fi
}

disable_linger() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping linger disable"
    return 0
  fi

  info "Disabling linger for user: $u"
  loginctl disable-linger "$u" 2>/dev/null || warn "Failed to disable linger for $u"
}

remove_sysctl_config() {
  local sysctl_file="/etc/sysctl.d/99-cloudflared.conf"
  
  if [[ -f "$sysctl_file" ]]; then
    info "Removing sysctl configuration: $sysctl_file"
    rm -f "$sysctl_file"
    sysctl --system >/dev/null 2>&1 || warn "Failed to reload sysctl settings"
  else
    warn "sysctl configuration not found: $sysctl_file"
  fi
}

remove_cloudflare_routes() {
  info "Removing Cloudflare IPv4 prefix routes from all interfaces"

  # Try to download current Cloudflare prefix list
  local cf_prefix_file
  cf_prefix_file=$(download_cloudflare_ipv4_prefixes || echo "")
  
  local -a cf_ipv4_prefixes
  
  if [[ -n "$cf_prefix_file" && -f "$cf_prefix_file" ]]; then
    mapfile -t cf_ipv4_prefixes < <(read_cloudflare_prefixes_from_file "$cf_prefix_file")
    rm -f "$cf_prefix_file"
  else
    # Fallback to hardcoded common Cloudflare prefixes
    warn "Could not download Cloudflare prefixes; using fallback list"
    cf_ipv4_prefixes=(
      "173.245.48.0/20"
      "103.21.244.0/22"
      "103.22.200.0/22"
      "103.31.4.0/22"
      "141.101.64.0/18"
      "108.162.192.0/18"
      "190.93.240.0/20"
      "188.114.96.0/20"
      "197.234.240.0/22"
      "198.41.128.0/17"
      "162.158.0.0/15"
      "104.16.0.0/13"
      "104.24.0.0/14"
      "172.64.0.0/13"
      "131.0.72.0/22"
    )
  fi

  info "Removing ${#cf_ipv4_prefixes[@]} Cloudflare IPv4 prefix routes from runtime"
  
  # Remove runtime routes (ignore errors if they don't exist)
  for prefix in "${cf_ipv4_prefixes[@]}"; do
    ip route del "$prefix" 2>/dev/null || true
  done

  # Remove from NetworkManager if active
  if is_systemctl_active NetworkManager.service && command -v nmcli >/dev/null 2>&1; then
    info "Removing Cloudflare routes from all NetworkManager connection profiles"

    # Get all active connections
    local connections
    mapfile -t connections < <(nmcli -t -f NAME con show --active | awk -F: '{print $1}')
    
    for con in "${connections[@]}"; do
      [[ -z "$con" ]] && continue
      
      local routes_removed=0
      for prefix in "${cf_ipv4_prefixes[@]}"; do
        if nmcli -g ipv4.routes con show "$con" 2>/dev/null | grep -q "$prefix"; then
          nmcli con mod "$con" -ipv4.routes "$prefix" 2>/dev/null && ((routes_removed++)) || true
        fi
      done
      
      if [[ $routes_removed -gt 0 ]]; then
        info "  Removed $routes_removed Cloudflare routes from connection: $con"
        nmcli con up "$con" >/dev/null 2>&1 || warn "Failed to bring up connection: $con"
      fi
    done
  else
    info "NetworkManager not active; runtime routes removed only"
  fi
  
  info "Cloudflare routes removed"
}

remove_rfc1918_routes() {
  local eth1_iface="${1:-eth1}"
  
  if ! iface_exists "$eth1_iface"; then
    warn "Interface $eth1_iface does not exist; skipping RFC1918 route removal"
    return 0
  fi
  
  info "Removing RFC1918 static routes from ${eth1_iface}"

  # Remove runtime routes (ignore errors if they don't exist)
  ip route del 10.0.0.0/8 dev "$eth1_iface" 2>/dev/null || true
  ip route del 172.16.0.0/12 dev "$eth1_iface" 2>/dev/null || true
  ip route del 192.168.0.0/16 dev "$eth1_iface" 2>/dev/null || true

  # Remove from NetworkManager if active
  if is_systemctl_active NetworkManager.service && command -v nmcli >/dev/null 2>&1; then
    info "Removing RFC1918 routes from NetworkManager ${eth1_iface} connection profile"

    local con1
    con1="$(get_nmcli_con_for_dev "$eth1_iface" || true)"
    
    if [[ -n "$con1" ]]; then
      # Remove the static routes
      nmcli con mod "$con1" -ipv4.routes "10.0.0.0/8" 2>/dev/null || true
      nmcli con mod "$con1" -ipv4.routes "172.16.0.0/12" 2>/dev/null || true
      nmcli con mod "$con1" -ipv4.routes "192.168.0.0/16" 2>/dev/null || true
      
      # Re-enable default route capability on eth1 (remove never-default flag)
      nmcli con mod "$con1" ipv4.never-default no 2>/dev/null || true
      
      nmcli con up "$con1" >/dev/null 2>&1 || warn "Failed to bring up connection: $con1"
      
      info "RFC1918 routes removed from NetworkManager"
    else
      warn "No active NetworkManager connection found for ${eth1_iface}"
    fi
  else
    info "NetworkManager not active; runtime routes removed only"
  fi
}

restore_default_route_to_eth0() {
  local eth0_iface="${1:-eth0}"
  
  if ! iface_exists "$eth0_iface"; then
    warn "Interface $eth0_iface does not exist; cannot restore default route"
    return 0
  fi
  
  info "Restoring default route to ${eth0_iface}"

  # Prompt for eth0 gateway IP
  local eth0_gw=""
  
  # Try to detect eth0 gateway from existing routes
  eth0_gw="$(ip route show | grep "${eth0_iface}.*metric" | awk '{print $3}' | head -n1 || true)"
  
  if [[ -z "$eth0_gw" ]]; then
    # Try to get from NetworkManager
    if is_systemctl_active NetworkManager.service && command -v nmcli >/dev/null 2>&1; then
      local con0
      con0="$(get_nmcli_con_for_dev "$eth0_iface" || true)"
      if [[ -n "$con0" ]]; then
        eth0_gw="$(nmcli -g ipv4.gateway con show "$con0" 2>/dev/null || true)"
      fi
    fi
  fi
  
  # Prompt if we couldn't detect the gateway
  if [[ -z "$eth0_gw" ]]; then
    echo
    read -r -p "Enter gateway IP for ${eth0_iface} (or press Enter to skip default route restoration): " eth0_gw
    [[ -z "$eth0_gw" ]] && { warn "Skipping default route restoration"; return 0; }
    
    if ! is_ipv4 "$eth0_gw"; then
      warn "Invalid IPv4 address: ${eth0_gw}; skipping default route restoration"
      return 0
    fi
  fi
  
  info "Using gateway ${eth0_gw} for ${eth0_iface}"

  # Remove any existing default routes
  info "Removing existing default routes..."
  ip route del default 2>/dev/null || true

  # Add default route via eth0
  info "Adding default route via ${eth0_iface} gateway ${eth0_gw}"
  ip route add default via "$eth0_gw" dev "$eth0_iface"

  # Persist via NetworkManager if active
  if is_systemctl_active NetworkManager.service && command -v nmcli >/dev/null 2>&1; then
    info "Persisting default route in NetworkManager ${eth0_iface} connection profile"

    local con0
    con0="$(get_nmcli_con_for_dev "$eth0_iface" || true)"
    
    if [[ -n "$con0" ]]; then
      # Set eth0 to be the default route
      nmcli con mod "$con0" ipv4.never-default no
      nmcli con mod "$con0" ipv6.never-default no
      nmcli con mod "$con0" ipv4.gateway "$eth0_gw"
      
      nmcli con up "$con0" >/dev/null 2>&1 || warn "Failed to bring up connection: $con0"
      
      info "Default route restored and persisted in NetworkManager"
    else
      warn "No active NetworkManager connection found for ${eth0_iface}"
      info "Default route added at runtime but not persisted"
    fi
  else
    info "NetworkManager not active; default route added at runtime only"
  fi
  
  # Verify the route
  info "Current default route:"
  ip route show default | sed 's/^/  /'
}

remove_journaling_config() {
  local journal_conf="/etc/systemd/journald.conf.d/99-persistent.conf"
  
  if [[ -f "$journal_conf" ]]; then
    info "Removing persistent journaling configuration: $journal_conf"
    rm -f "$journal_conf"
    
    # Optionally restart journald to apply changes
    read -r -p "Restart systemd-journald to apply changes? [y/N]: " restart_journal
    if [[ "${restart_journal,,}" == "y" ]]; then
      systemctl restart systemd-journald.service
      info "systemd-journald restarted"
    else
      warn "Journald configuration removed but service not restarted. Changes will apply after reboot."
    fi
  else
    warn "Journaling configuration not found: $journal_conf"
  fi
}

remove_user_account() {
  local u="$1"
  
  if ! user_exists "$u"; then
    warn "User $u does not exist; skipping user removal"
    return 0
  fi

  info "Removing user account: $u (including home directory)"
  userdel -r "$u" 2>/dev/null || warn "Failed to remove user $u"
}

main() {
  require_root

  echo "=========================================="
  echo "Cloudflared Container Uninstall Script"
  echo "=========================================="
  echo

  read -r -p "Enter the username that runs cloudflared: " CF_USER
  [[ -n "${CF_USER}" ]] || die "Username cannot be empty"

  if ! user_exists "${CF_USER}"; then
    warn "User ${CF_USER} does not exist. Some cleanup steps will be skipped."
  fi

  echo
  read -r -p "Was this server configured with 2 NICs and RFC1918 routes? [y/N]: " TWO_NICS
  TWO_NICS="${TWO_NICS,,}"
  
  if [[ "$TWO_NICS" == "y" ]]; then
    read -r -p "Enter the secondary interface name [eth1]: " SECONDARY_IFACE
    SECONDARY_IFACE="${SECONDARY_IFACE:-eth1}"
  fi

  echo
  read -r -p "Enter the primary interface name to restore default route [eth0]: " PRIMARY_IFACE
  PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

  echo
  echo "Starting uninstall process..."
  echo

  # 1. Stop and disable service
  stop_and_disable_service "${CF_USER}"

  # 2. Remove container and images
  remove_container_and_image "${CF_USER}"

  # 3. Remove Quadlet configuration
  remove_quadlet_files "${CF_USER}"

  # 4. Disable linger
  disable_linger "${CF_USER}"

  # 5. Remove sysctl configuration
  remove_sysctl_config

  # 6. Remove Cloudflare IPv4 prefix routes
  echo
  read -r -p "Remove Cloudflare IPv4 prefix routes? [Y/n]: " REMOVE_CF_ROUTES
  REMOVE_CF_ROUTES="${REMOVE_CF_ROUTES:-y}"
  if [[ "${REMOVE_CF_ROUTES,,}" == "y" ]]; then
    remove_cloudflare_routes
  else
    info "Skipping Cloudflare route removal"
  fi

  # 7. Remove RFC1918 routes if configured
  if [[ "$TWO_NICS" == "y" ]]; then
    echo
    remove_rfc1918_routes "${SECONDARY_IFACE}"
  else
    info "Skipping RFC1918 route removal (single NIC setup)"
  fi

  # 8. Restore default route to eth0
  echo
  read -r -p "Restore default route to ${PRIMARY_IFACE}? [Y/n]: " RESTORE_DEFAULT
  RESTORE_DEFAULT="${RESTORE_DEFAULT:-y}"
  if [[ "${RESTORE_DEFAULT,,}" == "y" ]]; then
    restore_default_route_to_eth0 "${PRIMARY_IFACE}"
  else
    info "Skipping default route restoration"
  fi

  # 9. Remove journaling configuration
  echo
  read -r -p "Remove persistent journaling configuration? [y/N]: " REMOVE_JOURNAL
  if [[ "${REMOVE_JOURNAL,,}" == "y" ]]; then
    remove_journaling_config
  else
    info "Keeping persistent journaling configuration"
  fi

  # 10. Optionally remove user account
  echo
  read -r -p "Remove user account '${CF_USER}' and home directory? [y/N]: " REMOVE_USER
  if [[ "${REMOVE_USER,,}" == "y" ]]; then
    remove_user_account "${CF_USER}"
  else
    info "Keeping user account: ${CF_USER}"
  fi

  echo
  info "=========================================="
  info "Uninstall complete!"
  info "=========================================="
  echo
  info "The following items were processed:"
  echo "  - cloudflared service stopped and disabled"
  echo "  - Container and images removed"
  echo "  - Quadlet configuration removed"
  echo "  - User linger disabled"
  echo "  - Sysctl configuration removed"
  [[ "${REMOVE_CF_ROUTES,,}" == "y" ]] && echo "  - Cloudflare IPv4 prefix routes removed"
  [[ "$TWO_NICS" == "y" ]] && echo "  - RFC1918 routes removed from ${SECONDARY_IFACE}"
  [[ "${RESTORE_DEFAULT,,}" == "y" ]] && echo "  - Default route restored to ${PRIMARY_IFACE}"
  [[ "${REMOVE_JOURNAL,,}" == "y" ]] && echo "  - Journaling configuration removed"
  [[ "${REMOVE_USER,,}" == "y" ]] && echo "  - User account removed"
  echo
  info "Verify routing configuration:"
  echo "  ip route show"
  echo "  ip route get 8.8.8.8"
  echo
  info "Note: Packages (podman, passt) were not removed. Uninstall manually if needed:"
  echo "  sudo dnf remove podman passt"
  echo
}

main "$@"
