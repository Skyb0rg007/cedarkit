{
  lib,
  rustPlatform,
  pkg-config,
  wrapGAppsHook4,
  gtk4,
  libadwaita,
  linux-pam,
}:

let
  root = ../.;
in
rustPlatform.buildRustPackage {
  pname = "cedarkit";
  version = "0.1.0";

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/crates")
      (root + "/policies")
      (root + "/state")
      (root + "/data")
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    wrapGAppsHook4
  ];
  buildInputs = [
    gtk4
    libadwaita
    linux-pam
  ];

  # Only the GTK agent needs GTK's environment.
  dontWrapGApps = true;
  postFixup = ''
    wrapGApp $out/bin/cedarkit-agent
  '';

  postInstall = ''
    # Vendor files, laid out as /usr/share/cedarkit.
    mkdir -p $out/share/cedarkit
    cp -r policies/. $out/share/cedarkit/

    install -Dm644 data/org.cedarkit.Authority1.conf \
      $out/share/dbus-1/system.d/org.cedarkit.Authority1.conf
    # Only installed in place of polkit's, by the NixOS module.
    install -Dm644 data/org.freedesktop.PolicyKit1.conf \
      $out/share/cedarkit-polkit/dbus-1/system.d/org.freedesktop.PolicyKit1.conf
    install -Dm644 data/cedarkit-agent.desktop \
      $out/etc/xdg/autostart/cedarkit-agent.desktop
  '';

  meta = {
    description = "A polkit alternative using the Cedar policy language";
    license = with lib.licenses; [
      mit
      asl20
    ];
    platforms = lib.platforms.linux;
    mainProgram = "cedarctl";
  };
}
