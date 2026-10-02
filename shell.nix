{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  packages = with pkgs; [
    cargo
    rustc
    clippy
    rustfmt
    rust-analyzer
  ];

  RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
  RUST_LOG = "cedarkit_core=debug,cedarkitd=debug";
}
