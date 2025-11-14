{
  description = "Waybar LAN widget - monitors devices on local network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "waybar_lan";
          version = "0.1.0";

          src = ./.;

          cargoLock = { lockFile = ./Cargo.lock; };

          meta = with pkgs.lib; {
            description = "Waybar LAN widget for monitoring local network devices";
            longDescription = ''
              A Rust-based LAN network monitor for Waybar that identifies and monitors
              all devices connected to the machine's local network interfaces, including
              Wi-Fi networks. Outputs Waybar-compatible JSON format with comprehensive
              network device information using type-safe domain modeling and zero-cost
              abstractions.
            '';
            license = licenses.mit;
            maintainers = [ ];
            platforms = platforms.linux;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.rust-analyzer
          ];

          shellHook = ''
            echo "waybar_lan development environment"
            echo "Rust toolchain: ${rustToolchain}"
            echo "Run 'cargo build' to build the project"
            echo "Run 'cargo run' to monitor local network"
          '';
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/waybar_lan";
        };
      });
}
