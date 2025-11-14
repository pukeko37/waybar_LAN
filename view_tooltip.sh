#!/usr/bin/env bash
# Display waybar_lan tooltip with colors in terminal

./target/release/waybar_lan | jq -r '.tooltip' | sed \
    -e "s|<span color='#00FF00'>\([^<]*\)</span>|\x1b[92m\1\x1b[0m|g" \
    -e "s|<span color='#FFFF00'>\([^<]*\)</span>|\x1b[93m\1\x1b[0m|g" \
    -e "s|<span color='#888888'>\([^<]*\)</span>|\x1b[90m\1\x1b[0m|g"
