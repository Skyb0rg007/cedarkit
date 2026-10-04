{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.cedarkit;

  layout = [
    "--vendor"
    "${cfg.package}/share/cedarkit"
    "--admin"
    "/etc/cedarkit"
    "--subject-schema"
    "/var/lib/cedarkit/subject.cedarschema"
  ];

  # In place of polkit's: org.freedesktop.PolicyKit1 is activated as
  # cedarkitd, and root may own it.
  polkitBus = pkgs.runCommand "cedarkit-polkit-dbus" { } ''
    mkdir -p $out/share/dbus-1/system-services
    cp -r ${cfg.package}/share/cedarkit-polkit/dbus-1/system.d $out/share/dbus-1/
    cat > $out/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service <<EOF
    [D-BUS Service]
    Name=org.freedesktop.PolicyKit1
    Exec=/run/current-system/sw/bin/false
    User=root
    SystemdService=cedarkitd.service
    EOF
  '';

  authorityBus = pkgs.writeTextDir "share/dbus-1/system-services/org.cedarkit.Authority1.service" ''
    [D-BUS Service]
    Name=org.cedarkit.Authority1
    Exec=/run/current-system/sw/bin/false
    User=root
    SystemdService=cedarkitd.service
  '';
in
{
  options.services.cedarkit = {
    enable = mkEnableOption "CedarKit, a polkit alternative using the Cedar policy language";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The CedarKit package.";
    };

    polkit = mkEnableOption ''
      serving polkit's interface, `org.freedesktop.PolicyKit1`, in place of
      polkitd. polkit's client tools and authentication agent helper stay
      installed, so polkit agents such as `pkttyagent` work with CedarKit
    '';

    fillMissingDetails = mkEnableOption ''
      making up resources when mechanisms don't pass the polkit details
      that identify them, as unpatched systemd doesn't, rather than denying
      the check
    '';

    rememberSeconds = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = "How long to remember authentications. By default, 300 seconds, as polkit.";
    };

    policies = mkOption {
      type = types.attrsOf types.lines;
      default = { };
      example = {
        "netadmin.entities.json" = ''
          [{ "uid": { "type": "Group", "id": "netadmin" },
             "parents": [{ "type": "Role", "id": "org.freedesktop.network1.admin" }] }]
        '';
      };
      description = ''
        The local admin's files, in /etc/cedarkit/local: schemas
        (`*.cedarschema`), policies (`*.cedar`) and role memberships
        (`*.entities.json`), by file name.
      '';
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra arguments for cedarkitd.";
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [ cfg.package ];
      services.dbus.packages = [
        cfg.package
        authorityBus
      ];
      security.pam.services.cedarkit = { };

      environment.etc = lib.mapAttrs' (
        name: text: lib.nameValuePair "cedarkit/local/${name}" { inherit text; }
      ) cfg.policies;

      systemd.services.cedarkitd = {
        description = "CedarKit authority";
        wantedBy = [ "multi-user.target" ];
        after = [ "dbus.service" ];
        restartTriggers = lib.mapAttrsToList (name: _: config.environment.etc."cedarkit/local/${name}".source) cfg.policies;
        serviceConfig = {
          Type = "dbus";
          BusName = "org.cedarkit.Authority1";
          StateDirectory = "cedarkit";
          RuntimeDirectory = "cedarkit";
          RuntimeDirectoryMode = "0755";
          # The subject schema, for the installed fact providers, as a
          # package hook would.
          ExecStartPre = lib.escapeShellArgs ([ "${cfg.package}/bin/cedarctl" ] ++ layout ++ [ "schema" "update" ]);
          ExecStart = lib.escapeShellArgs (
            [ "${cfg.package}/bin/cedarkitd" ]
            ++ layout
            ++ lib.optional cfg.polkit "--polkit"
            ++ lib.optional cfg.fillMissingDetails "--fill-missing-details"
            ++ lib.optionals (cfg.rememberSeconds != null) [
              "--remember-seconds"
              (toString cfg.rememberSeconds)
            ]
            ++ cfg.extraArgs
          );
          Environment = "RUST_LOG=cedarkitd=info,cedarkit_core=info";
        };
      };
    }

    (mkIf cfg.polkit {
      assertions = [
        {
          assertion = !config.security.polkit.enable;
          message = "services.cedarkit.polkit replaces polkitd: disable security.polkit.enable.";
        }
      ];

      services.dbus.packages = [ polkitBus ];
      # polkit's tools, and its agent helper, which agents such as
      # pkttyagent use and which reports to org.freedesktop.PolicyKit1.
      environment.systemPackages = [ pkgs.polkit.bin ];
      systemd.packages = [ pkgs.polkit.out ];
      systemd.sockets."polkit-agent-helper".wantedBy = [ "sockets.target" ];
      systemd.services."polkit-agent-helper@".serviceConfig.StandardError = "journal";
      systemd.services.polkit.enable = false;
      security.pam.services.polkit-1 = { };
      # As NixOS's systemd module does when polkit is enabled: run0
      # authenticates through polkit, then needs this to run the command.
      security.pam.services.systemd-run0 = {
        setLoginUid = true;
        pamMount = false;
      };
      environment.pathsToLink = [ "/share/polkit-1" ];
    })
  ]);
}
