#!/bin/bash
set -euo pipefail

PROFILE_NAME="custom-parallel-auth"
SO_NAME="pam_parallel_auth.so"
SO_SRC="target/release/libpam_parallel_auth.so"
SO_DEST="/usr/lib64/security/${SO_NAME}"
PROFILE_SRC="authselect/${PROFILE_NAME}"
PROFILE_DEST="/etc/authselect/custom/${PROFILE_NAME}"

# 1. Build (as current user, not root)
echo "==> Building release..."
cargo build --release

# 2. Install .so
echo "==> Installing ${SO_DEST}"
sudo install -m 755 "${SO_SRC}" "${SO_DEST}"

# 3. Install authselect profile
echo "==> Installing authselect profile to ${PROFILE_DEST}"
sudo mkdir -p "${PROFILE_DEST}"
sudo cp -a "${PROFILE_SRC}/." "${PROFILE_DEST}/"

# 4. Select profile
echo "==> Activating profile: ${PROFILE_NAME} with-parallel-auth"
sudo authselect select "custom/${PROFILE_NAME}" with-parallel-auth --force

echo ""
echo "Done! Test with: sudo echo success"
echo ""
echo "To revert:"
echo "  sudo authselect select local  # or your previous profile"
