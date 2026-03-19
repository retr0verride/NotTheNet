#!/usr/bin/env bash
cat > /usr/local/bin/notthenet-gui << 'EOF'
#!/usr/bin/env bash
SCRIPT="/home/kali/NotTheNet/notthenet.py"

if [[ $EUID -eq 0 ]]; then
    [[ -n "$NTN_DISPLAY" ]]    && export DISPLAY="$NTN_DISPLAY"
    [[ -n "$NTN_XAUTHORITY" ]] && export XAUTHORITY="$NTN_XAUTHORITY"
    exec python3 "$SCRIPT" "$@"
fi

if command -v pkexec &>/dev/null; then
    pkexec env NTN_DISPLAY="$DISPLAY" NTN_XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
        "$(readlink -f "$0")" "$@"
    _rc=$?
    [[ $_rc -eq 126 ]] && exit 0
    [[ $_rc -eq 127 ]] || exit $_rc
fi

if command -v xterm &>/dev/null; then
    exec xterm -T "NotTheNet" \
        -e "sudo DISPLAY='$DISPLAY' XAUTHORITY='${XAUTHORITY:-$HOME/.Xauthority}' python3 '$SCRIPT' || { echo; read -rp 'Press Enter to close...'; }"
fi

echo "Run: sudo python3 $SCRIPT" >&2
exit 1
EOF
chmod +x /usr/local/bin/notthenet-gui
echo "Done."
