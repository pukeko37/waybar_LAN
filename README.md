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
