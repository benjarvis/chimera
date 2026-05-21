#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: Unlicense

# Usage: kvm_pnfs_test_wrapper.sh <vmlinuz> <rootfs.qcow2> <chimera_binary> <backend> <nfsver> <test_cmd>
#
# Orchestrates an NFSv4.1 pNFS setup and a QEMU VM to exercise it:
# 1. Starts a chimera *data server* (memfs in ds_mode) on 10.0.0.1:2050,
#    binding only the NFS service (data_server mode).
# 2. Reads the data server's memfs mount_id from its log.
# 3. Starts a chimera *metadata server* (pNFS enabled, the given backend) on
#    10.0.0.1:2049, pointing its single data server at 10.0.0.1:2050.
# 4. Boots a QEMU VM which mounts the MDS with vers=4.1 and runs the test.
#
# Because the MDS keeps no data for pNFS-backed files (it returns EIO for any
# READ/WRITE that does not go through a layout), a workload that successfully
# reads back what it wrote proves the client used pNFS to reach the data
# server -- there is no MDS-side fallback that could mask a broken layout.

set -u

ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    QEMU_BIN="qemu-system-aarch64"
    QEMU_MACHINE="-machine virt"
    QEMU_CONSOLE="ttyAMA0"
else
    QEMU_BIN="qemu-system-x86_64"
    QEMU_MACHINE="-machine q35,usb=off"
    QEMU_CONSOLE="ttyS0"
fi

VMLINUZ=$1; shift
ROOTFS=$1; shift
CHIMERA_BINARY=$1; shift
BACKEND=$1; shift
NFS_VERSION=$1; shift
TEST_CMD_ARG="$*"

# pNFS requires NFSv4.1+.
case "$NFS_VERSION" in
    4.1 | 4.2) ;;
    *) echo "pNFS test requires NFS 4.1+, got ${NFS_VERSION}" >&2; exit 1 ;;
esac

INITRD="$(dirname "$VMLINUZ")/initrd"
if [ -f "$INITRD" ]; then
    QEMU_INITRD="-initrd $INITRD"
else
    QEMU_INITRD=""
fi

NETNS_NAME="kvm_pnfs_$$_$(date +%s%N)"
TAP_NAME="tap_$$"
LOG_FILE=$(mktemp /tmp/kvm_pnfs_test_XXXXXX.log)
BUILD_DIR=$(dirname "$(dirname "$CHIMERA_BINARY")")
SESSION_DIR=$(mktemp -d "${BUILD_DIR}/kvm_pnfs_session_XXXXXX")
MDS_CONFIG="${SESSION_DIR}/mds.json"
DS_CONFIG="${SESSION_DIR}/ds.json"
DS_LOG="${SESSION_DIR}/ds.log"
MDS_PID=""
DS_PID=""

MDS_IP="10.0.0.1"
DS_IP="10.0.0.1"
MDS_PORT=2049
DS_PORT=2050
# RFC 5665 universal address for DS_IP:2050 -> port 2050 = 8*256 + 2
DS_UADDR="${DS_IP}.8.2"

cleanup() {
    for pid in "$MDS_PID" "$DS_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            for i in $(seq 1 30); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [ -f "$LOG_FILE" ]; then
        echo "=== Guest serial log ==="
        cat "$LOG_FILE"
    fi
    if [ -f "$DS_LOG" ]; then
        echo "=== Data server log (tail) ==="
        tail -20 "$DS_LOG"
    fi
    ip netns delete "${NETNS_NAME}" 2>/dev/null || true
    rm -f "$LOG_FILE"
    rm -rf "$SESSION_DIR"
}
trap cleanup EXIT

# The data server is always memfs in ds_mode: it stores only the file data
# that pNFS clients write directly, addressed by handles minted by the MDS.
generate_ds_config() {
    cat > "$DS_CONFIG" << EOF
{
    "server": {
        "threads": 2,
        "nfs_port": ${DS_PORT},
        "data_server": true,
        "external_portmap": true,
        "metrics_port": 9001,
        "vfs": { "memfs": { "config": { "ds_mode": true } } }
    },
    "mounts": { "ds_data": { "module": "memfs", "path": "/" } },
    "exports": { "/ds": { "path": "/ds_data" } }
}
EOF
}

# The metadata server runs the namespace on the requested backend and steers
# file data to the data server announced via server.pnfs.
generate_mds_config() {
    local ds_mount_id="$1"
    local mount_path="/"

    case "$BACKEND" in
        memfs) mount_path="/" ;;
        *) echo "pNFS test only supports the memfs backend, got ${BACKEND}" >&2; exit 1 ;;
    esac

    cat > "$MDS_CONFIG" << EOF
{
    "server": {
        "threads": 4,
        "external_portmap": false,
        "pnfs": {
            "enabled": true,
            "data_servers": [
                { "mount_id": "${ds_mount_id}", "netid": "tcp", "uaddr": "${DS_UADDR}" }
            ]
        }
    },
    "mounts": { "share": { "module": "${BACKEND}", "path": "${mount_path}" } },
    "exports": { "/share": { "path": "/share" } }
}
EOF
}

wait_for_port() {
    local ip="$1" port="$2" pid="$3"
    for i in $(seq 1 50); do
        if ip netns exec "${NETNS_NAME}" bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "chimera daemon (pid $pid) exited prematurely" >&2
            return 1
        fi
        sleep 0.1
    done
    echo "timed out waiting for ${ip}:${port}" >&2
    return 1
}

ulimit -l unlimited
echo 16777216 > /proc/sys/fs/aio-max-nr 2>/dev/null || true

# Network namespace + TAP for the VM.
ip netns add "${NETNS_NAME}"
ip netns exec "${NETNS_NAME}" ip link set lo up
ip netns exec "${NETNS_NAME}" ip tuntap add dev "${TAP_NAME}" mode tap
ip netns exec "${NETNS_NAME}" ip addr add 10.0.0.1/24 dev "${TAP_NAME}"
ip netns exec "${NETNS_NAME}" ip link set "${TAP_NAME}" up

# 1. Start the data server and learn its mount_id.
generate_ds_config
ip netns exec "${NETNS_NAME}" "$CHIMERA_BINARY" -c "$DS_CONFIG" > "$DS_LOG" 2>&1 &
DS_PID=$!
wait_for_port "$DS_IP" "$DS_PORT" "$DS_PID" || exit 1

DS_MOUNT_ID=$(grep -oP 'memfs mount_id \K[0-9a-f]{32}' "$DS_LOG" | tail -1)
if [ -z "$DS_MOUNT_ID" ]; then
    echo "could not determine data server mount_id" >&2
    exit 1
fi
echo "=== pNFS data server up on ${DS_IP}:${DS_PORT}, mount_id ${DS_MOUNT_ID} ==="

# 2. Start the metadata server pointing at that data server.
generate_mds_config "$DS_MOUNT_ID"
ip netns exec "${NETNS_NAME}" "$CHIMERA_BINARY" -c "$MDS_CONFIG" &
MDS_PID=$!
wait_for_port "$MDS_IP" "$MDS_PORT" "$MDS_PID" || exit 1
echo "=== pNFS metadata server up on ${MDS_IP}:${MDS_PORT} ==="

# 3. Boot the VM, mount the MDS with pNFS, run the workload.
NFS_MOUNT_OPTS="vers=${NFS_VERSION},tcp"
TEST_CMD="mount -t nfs -o ${NFS_MOUNT_OPTS} ${MDS_IP}:/share /mnt && ${TEST_CMD_ARG}"

ip netns exec "${NETNS_NAME}" "$QEMU_BIN" \
    -enable-kvm -smp 4 -m 1G -cpu host \
    -kernel "$VMLINUZ" \
    $QEMU_INITRD \
    $QEMU_MACHINE \
    -nodefaults \
    -drive file="$ROOTFS",if=virtio,format=qcow2,snapshot=on \
    -netdev tap,id=net0,ifname="${TAP_NAME}",script=no,downscript=no \
    -device virtio-net-pci,netdev=net0,romfile="" \
    -serial stdio \
    -nographic \
    -no-reboot \
    -append "root=/dev/vda rw console=${QEMU_CONSOLE} net.ifnames=0 biosdevname=0 quiet panic=-1 test_cmd=\"${TEST_CMD}\" init=/init.sh" \
    2>/dev/null | tee "$LOG_FILE"

for pid in "$MDS_PID" "$DS_PID"; do
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null
        echo "=== A chimera daemon (pid $pid) DIED during the test (exit $?) ==="
        [ "$pid" = "$MDS_PID" ] && MDS_PID=""
        [ "$pid" = "$DS_PID" ] && DS_PID=""
    fi
done

EXIT_CODE=$(grep -oP 'CHIMERA_KVM_EXIT_CODE=\K[0-9]+' "$LOG_FILE" | tail -1)
exit ${EXIT_CODE:-1}
