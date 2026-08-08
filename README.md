# Waybar LAN Widget

A Rust implementation of a LAN network monitor for Waybar. This executable identifies and monitors all devices connected to the machine's local network interfaces, including Wi-Fi networks, and outputs Waybar-compatible JSON format.

## Features

- Monitors all local network interfaces (Ethernet, Wi-Fi, etc.)
- Identifies devices connected to the local network
- Outputs Waybar-compatible JSON format with text and tooltip
- Robust error handling with informative messages
- Lightweight and minimal dependencies

## Architecture

This project follows the three-layer Waybar widget architecture:

- **Domain layer** (`domain/`): Type-safe network data models with validation
- **Data layer** (`data/`): Network interface data collection from system
- **Display layer** (`display/`): Waybar JSON formatting

## Installation

### For Nix Users

This project provides a Nix flake for reproducible builds and easy integration with NixOS.

#### Quick Start with Nix

```bash
# Run directly from GitHub
nix run github:pukeko37/waybar_LAN

# Build locally
nix build

# The binary will be available at ./result/bin/waybar_lan
./result/bin/waybar_lan
```

#### Add to NixOS Configuration

Add this flake as an input in your NixOS configuration:

```nix
# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    waybar-lan.url = "github:pukeko37/waybar_LAN";
  };

  outputs = { self, nixpkgs, waybar-lan, ... }: {
    nixosConfigurations.yourhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        {
          environment.systemPackages = [
            waybar-lan.packages.x86_64-linux.default
          ];
        }
      ];
    };
  };
}
```

#### Use in Home Manager

```nix
# home.nix
{ inputs, pkgs, ... }: {
  home.packages = [
    inputs.waybar-lan.packages.${pkgs.system}.default
  ];
}
```

#### Development Shell

Enter a development environment with all required tools:

```bash
nix develop

# Now you have cargo, rust-analyzer, and other tools available
cargo build
cargo test
```

### Building with Cargo

```bash
cargo build --release
```

The binary will be available at `target/release/waybar_lan`.

## Usage

```bash
./target/release/waybar_lan
```

Run this way, the widget only sees this host's own local-vantage-point
data (`ip neigh`, mDNS, reverse DNS) — one flat `via {interface}` group
in the tooltip, no router-sourced devices.

### Testing with the router integration enabled

Most of the tooltip's structure — the `via WireGuard`, `via Wi-Fi`, and
`Other` groups, WAN address, gateway DNS enrichment — only appears once a
router is configured. `WAYBAR_LAN_ROUTER` is read fresh from the
environment on every invocation, so it's a per-command flag, not a build
setting:

```bash
WAYBAR_LAN_ROUTER=user@host ./target/release/waybar_lan
```

`user@host` is an OpenWrt router reachable over SSH, restricted to the
dispatcher command whitelist described in `infra-router-module-rules`
(see the project wiki) — not a general-purpose SSH account. Unset
entirely, behaviour is identical to omitting the variable: no SSH is
attempted, and no other behaviour changes.

To eyeball the tooltip instead of raw JSON, `view_tooltip.sh` wraps the
same call and renders the Pango colour spans as ANSI:

```bash
WAYBAR_LAN_ROUTER=user@host ./view_tooltip.sh
```

A deployed widget (e.g. via a NixOS/home-manager config) sets this env
var alongside its `exec` line — check that config for whether router
integration is actually enabled in production before assuming local-only
output matches what's deployed.

`--dump-devices <DIR>` (optionally with `--sanitize`) dumps this host's
raw pre-filter local collection to JSON files for diagnosis — see
`--help`. It does not currently include router-sourced raw data.

## Output Format

The program outputs JSON in the Waybar format:

```json
{
  "text": "🖧 LAN",
  "tooltip": "Network information will appear here",
  "alt": "network",
  "class": ["network"]
}
```

## Dependencies

- `serde` and `serde_json` - JSON serialization/deserialization
- `anyhow` - Error handling

## Waybar Configuration

Example Waybar config (`~/.config/waybar/config`):

```json
{
    "custom/lan": {
        "format": "{}",
        "exec": "/path/to/waybar_lan/target/release/waybar_lan",
        "interval": 30,
        "return-type": "json",
        "tooltip": true
    }
}
```

Or for Nix users with the package installed:

```json
{
    "custom/lan": {
        "format": "{}",
        "exec": "waybar_lan",
        "interval": 30,
        "return-type": "json",
        "tooltip": true
    }
}
```

## Testing

```bash
cargo test
```

## License

See LICENSE file for details.
