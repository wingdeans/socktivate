{ pkgs ? import <nixpkgs> {
  overlays = [ (import <rust-overlay>) ];
}}:

pkgs.mkShell {
  packages = with pkgs; [
    (rust-bin.selectLatestNightlyWith
      (toolchain: toolchain.default.override {
        targets = [
          "x86_64-unknown-linux-gnu"
          "aarch64-unknown-linux-musl"
        ];
      }))
    pkgsCross.aarch64-multiplatform.stdenv.cc
  ];

  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "aarch64-unknown-linux-gnu-cc";
}
