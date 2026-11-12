#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
LAB="$PWD"
TOOLS="$LAB/tools"
DATA="$LAB/data"
HAYABUSA_VER="4.4.0"
CHAINSAW_VER="2.17.1"
mkdir -p "$TOOLS" "$DATA"

AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN"); fi

echo "==> Installing base packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq jq unzip >/dev/null

echo "==> Installing Hayabusa ${HAYABUSA_VER}..."
if [ ! -d "$TOOLS/hayabusa" ]; then
  URL=$(curl -fsSL "${AUTH[@]}" "https://api.github.com/repos/Yamato-Security/hayabusa/releases/tags/v${HAYABUSA_VER}" \
    | jq -r '.assets[].browser_download_url | select(test("lin-x64-gnu\\.zip$"))' | head -1)
  [ -n "$URL" ] || { echo "Hayabusa release not found"; exit 1; }
  curl -fsSL -o /tmp/hayabusa.zip "$URL"
  mkdir -p "$TOOLS/hayabusa"
  unzip -q /tmp/hayabusa.zip -d "$TOOLS/hayabusa"
  rm -f /tmp/hayabusa.zip
fi
HB_BIN=$(find "$TOOLS/hayabusa" -maxdepth 2 -type f -name "hayabusa-*-lin-x64-gnu" | head -1)
chmod +x "$HB_BIN"
sudo ln -sf "$HB_BIN" /usr/local/bin/hayabusa
if [ ! -d "$(dirname "$HB_BIN")/rules" ]; then
  (cd "$(dirname "$HB_BIN")" && hayabusa update-rules -q || true)
fi

echo "==> Installing Chainsaw ${CHAINSAW_VER}..."
if [ ! -x "$TOOLS/chainsaw/chainsaw" ]; then
  curl -fsSL "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VER}/chainsaw_x86_64-unknown-linux-gnu.tar.gz" \
    | tar -xz -C "$TOOLS"
  chmod +x "$TOOLS/chainsaw/chainsaw"
fi
sudo ln -sf "$TOOLS/chainsaw/chainsaw" /usr/local/bin/chainsaw

echo "==> Downloading Sigma rules..."
if [ ! -d "$TOOLS/sigma" ]; then
  git clone -q --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git "$TOOLS/sigma"
  git -C "$TOOLS/sigma" sparse-checkout set rules/windows
fi

echo "==> Pulling Zeek..."
docker pull -q zeek/zeek:latest >/dev/null
sudo ln -sf "$LAB/bin/zeek-run" /usr/local/bin/zeek-run
sudo ln -sf "$LAB/bin/zeek-cut" /usr/local/bin/zeek-cut
sudo ln -sf "$LAB/bin/hunt" /usr/local/bin/hunt
chmod +x "$LAB"/bin/zeek-run "$LAB"/bin/zeek-cut "$LAB"/bin/hunt

echo "==> Downloading datasets..."
[ -d "$DATA/evtx" ] || git clone -q --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git "$DATA/evtx"
[ -d "$DATA/pcap" ] || git clone -q --depth 1 https://github.com/sbousseaden/PCAP-ATTACK.git "$DATA/pcap"

echo "==> Preparing cases..."
place() {
  mkdir -p "$LAB/cases/$1/evidence"
  cp "$DATA/$2" "$LAB/cases/$1/evidence/$3"
}
place case-01 "evtx/Defense Evasion/DE_1102_security_log_cleared.evtx" "Security.evtx"
place case-02 "evtx/Credential Access/kerberos_pwd_spray_4771.evtx" "DC-Security.evtx"
place case-03 "evtx/Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx" "Sysmon.evtx"
place case-04 "evtx/Persistence/persistence_accessibility_features_osk_sysmon1.evtx" "Sysmon.evtx"
place case-05 "evtx/Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx" "Sysmon.evtx"
place case-06 "evtx/Credential Access/CA_DCSync_4662.evtx" "DC-Security.evtx"
place case-07 "pcap/Command and Control/cmds over dns txt queries and reponses.pcap" "traffic.pcap"

echo ""
echo "=============================================="
echo " SOC Hunting Lab is ready"
echo " Start with: cases/case-01/README.md"
echo "=============================================="
