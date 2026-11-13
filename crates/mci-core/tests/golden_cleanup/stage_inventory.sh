s="$HOME/.morpheus-certificate-install-stage"; [ -d "$s" ] && printf 'stage|%s|%s|%s\n' "$s" "$(du -sb "$s" | cut -f1)" "$(stat -c %Y "$s")"; true
