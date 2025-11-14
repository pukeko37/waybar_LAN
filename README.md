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

## Building

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
        "exec": "/path/to/waybar_lan",
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
