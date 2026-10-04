{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  packages = with pkgs; [
    cargo
    rustc
    clippy
    rustfmt
    rust-analyzer
  ];

  nativeBuildInputs = with pkgs; [
    pkg-config
  ];

  buildInputs = with pkgs; [
    # The authentication agent's GUI.
    gtk4
    libadwaita
    # The daemon's authentication helper.
    linux-pam
  ];

  RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
  RUST_LOG = "cedarkit_core=debug,cedarkitd=debug,cedarkit_agent=debug";
}
