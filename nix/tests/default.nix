# NixOS VM tests: CedarKit installed and running for real.
#
#   nix-build nix/tests -A native     # one test
#   nix-build nix/tests               # all of them
#
# Each test boots a VM with cedarkitd as a system service, and users alice
# (in wheel, so an admin) and bob, with alice logged in on tty1: an active
# local logind session. Commands typed there run as polkit's allow_active
# column; commands run with `su` from the test driver run outside any
# session.
{
  pkgs ? import <nixpkgs> { },
}:

let
  inherit (pkgs) lib;
  cedarkit = pkgs.callPackage ../package.nix { };
  vendor = "${cedarkit}/share/cedarkit";
  layout = "--vendor ${vendor} --admin /etc/cedarkit --subject-schema /var/lib/cedarkit/subject.cedarschema";

  # A check with the native interface: check ACTION RESOURCE [FLAGS] [TIMEOUT]
  check = pkgs.writeShellScriptBin "check" ''
    exec busctl call --timeout="''${4:-90}" org.cedarkit.Authority1 /org/cedarkit/Authority1 \
      org.cedarkit.Authority1 CheckAuthorization '(sa{sv})s(sa{sv}as)a{sv}us' \
      "" 0 "$1" "$2" 0 0 0 "''${3:-0}" ""
  '';

  base =
    { ... }:
    {
      imports = [ ../module.nix ];
      services.cedarkit = {
        enable = true;
        package = cedarkit;
      };
      users.users.alice = {
        isNormalUser = true;
        password = "alice-pw";
        extraGroups = [ "wheel" ];
      };
      users.users.bob = {
        isNormalUser = true;
        password = "bob-pw";
      };
      services.getty.autologinUser = "alice";
      environment.systemPackages = [
        check
        pkgs.jq
        pkgs.util-linux
      ];
    };

  # Helpers shared by the test scripts.
  prelude = ''
    import json
    import shlex

    counter = 0

    def login(m):
        """Waits for cedarkitd, and alice's shell on tty1."""
        m.wait_for_unit("cedarkitd.service")
        m.wait_until_tty_matches("1", "alice@")

    def start(m, cmd):
        """Types cmd into alice's shell on tty1, an active local session,
        with its output going to a file. Returns its number, for result()."""
        global counter
        counter += 1
        n = counter
        m.send_chars(f"({cmd}) >/tmp/out{n} 2>&1; echo $? >/tmp/rc{n}\n")
        return n

    def result(m, n, timeout=120):
        """The output and exit status of the command start() numbered n."""
        m.wait_for_file(f"/tmp/rc{n}", timeout)
        return m.succeed(f"cat /tmp/out{n}"), int(m.succeed(f"cat /tmp/rc{n}"))

    def tty(m, cmd):
        """Runs cmd in alice's shell on tty1, returning output and status."""
        return result(m, start(m, cmd))

    def background(m, cmd, log):
        """Starts cmd in the background in alice's shell, logging to log."""
        m.send_chars(f"{cmd} >{log} 2>&1 &\n")

    def outside(m, user, cmd):
        """Runs cmd as user, outside any login session."""
        return m.execute(f"su {user} -s /bin/sh -c {shlex.quote(cmd)} 2>&1")

    def stop_agents(m):
        """Stops any cedarkit-cli-agent: one agent per session."""
        # The brackets stop the patterns matching the shell running them.
        m.execute("pkill -f '[c]edarkit-cli-agent'")
        m.wait_until_fails("pgrep -f '[c]edarkit-cli-agent'")

    def agent(m, args, log):
        """Starts cedarkit-cli-agent in alice's session, once registered."""
        stop_agents(m)
        background(m, f"cedarkit-cli-agent {args}", log)
        m.wait_until_succeeds(f"grep -q registered {log}")

    def events(m, log):
        """The JSON events cedarkit-cli-agent logged."""
        return [json.loads(l) for l in m.succeed(f"cat {log}").splitlines() if l.startswith("{")]

    def clock():
        return "'systemd::Clock::\"system\"'"
  '';

  test =
    name: args:
    pkgs.testers.runNixOSTest (
      {
        inherit name;
        testScript = prelude + args.testScript;
      }
      // removeAttrs args [ "testScript" ]
    );

  polkitMode = {
    services.cedarkit.polkit = true;
  };
in
{
  # The native interface, the layout of files, and failing safely.
  native = test "cedarkit-native" {
    nodes.machine = base;
    testScript = ''
      m = machine
      login(m)
      m.succeed("test -s /var/lib/cedarkit/subject.cedarschema")
      m.succeed("cedarctl ${layout} validate")

      with subtest("decisions follow logind's facts"):
          out, _ = tty(m, "check org.freedesktop.login1.reboot 'systemd::System::\"local\"'")
          assert '"allow"' in out, out
          out, _ = tty(m, f"check org.freedesktop.timedate1.set-time {clock()}")
          assert '"challenge"' in out and '"alice"' in out, out
          # A process outside any session counts as in its user's display
          # session, as in polkit: for alice, the active one on tty1.
          _, out = outside(m, "alice", "check org.freedesktop.login1.reboot 'systemd::System::\"local\"'")
          assert '"allow"' in out, out
          # bob has no session at all: polkit's allow_any column.
          _, out = outside(m, "bob", "check org.freedesktop.login1.reboot 'systemd::System::\"local\"'")
          assert '"challenge"' in out and '"alice"' in out, out

      with subtest("admins are asked for, not other users"):
          _, out = outside(m, "bob", f"check org.freedesktop.timedate1.set-time {clock()}")
          assert '"alice"' in out and '"bob"' not in out, out

      with subtest("users can't check for other users' processes"):
          status, out = outside(m, "bob",
              "busctl call org.cedarkit.Authority1 /org/cedarkit/Authority1 org.cedarkit.Authority1 "
              "CheckAuthorization '(sa{sv})s(sa{sv}as)a{sv}us' unix-process 1 pid u 1 "
              "org.freedesktop.login1.reboot 'systemd::System::\"local\"' 0 0 0 0 \"\"")
          assert status != 0 and "Access denied" in out, out

      with subtest("users can't give resource facts"):
          status, out = outside(m, "bob",
              "busctl call org.cedarkit.Authority1 /org/cedarkit/Authority1 org.cedarkit.Authority1 "
              "CheckAuthorization '(sa{sv})s(sa{sv}as)a{sv}us' \"\" 0 "
              "org.freedesktop.machine1.shell 'systemd::Machine::\"box\"' 1 owner '(ss)' User 1001 0 0 0 \"\"")
          assert status != 0 and "Access denied" in out, out

      with subtest("the local admin's policies apply"):
          m.succeed("mkdir -p /etc/cedarkit/local")
          m.succeed("echo '@id(\"local/no-reboot\") forbid (principal, action == Action::\"org.freedesktop.login1.reboot\", resource);' "
                    "> /etc/cedarkit/local/no-reboot.cedar")
          m.succeed("systemctl restart cedarkitd")
          out, _ = tty(m, "check org.freedesktop.login1.reboot 'systemd::System::\"local\"'")
          assert '"deny"' in out, out
          m.succeed("rm /etc/cedarkit/local/no-reboot.cedar && systemctl restart cedarkitd")

      with subtest("an admin file replaces the vendor file"):
          m.succeed("mkdir -p /etc/cedarkit/systemd && : > /etc/cedarkit/systemd/org.freedesktop.login1.cedar")
          m.succeed("systemctl restart cedarkitd")
          out, _ = tty(m, "check org.freedesktop.login1.reboot 'systemd::System::\"local\"'")
          assert '"deny"' in out, out
          m.succeed("rm -r /etc/cedarkit/systemd && systemctl restart cedarkitd")
          out, _ = tty(m, "check org.freedesktop.login1.reboot 'systemd::System::\"local\"'")
          assert '"allow"' in out, out

      with subtest("a broken file stops cedarkitd starting, naming it"):
          m.succeed("echo 'permit (' > /etc/cedarkit/local/broken.cedar")
          m.fail("systemctl restart cedarkitd")
          m.succeed("journalctl -u cedarkitd | grep -q broken.cedar")
          m.succeed("rm /etc/cedarkit/local/broken.cedar && systemctl restart cedarkitd")

      with subtest("vendor files are confined to their application"):
          m.succeed("cp -r ${vendor} /tmp/vendor && chmod -R u+w /tmp/vendor && mkdir /tmp/vendor/evil")
          m.succeed("echo 'permit (principal, action, resource);' > /tmp/vendor/evil/evil.cedar")
          status, out = m.execute("cedarctl --vendor /tmp/vendor --admin /etc/cedarkit "
                                  "--subject-schema /var/lib/cedarkit/subject.cedarschema validate 2>&1")
          assert status != 0 and "must name the actions" in out, out
    '';
  };

  # The native agent protocol, with the command-line agent and real PAM.
  agent = test "cedarkit-agent" {
    nodes.machine = base;
    testScript = ''
      m = machine
      login(m)

      with subtest("a wrong password, then the right one"):
          agent(m, "--answer wrong --answer alice-pw --requests 1", "/tmp/agent1")
          out, _ = tty(m, f"check org.freedesktop.timedate1.set-time {clock()} 1")
          assert '"allow"' in out, out
          results = [e["success"] for e in events(m, "/tmp/agent1") if e["event"] == "result"]
          assert results == [False, True], results
          m.succeed("journalctl -u cedarkitd | grep -q 'remembering the authentication'")

      with subtest("no agent: the challenge is returned"):
          stop_agents(m)
          out, _ = tty(m, f"check org.freedesktop.timedate1.set-time {clock()} 1")
          assert '"challenge"' in out, out

      with subtest("siblings in a terminal share a remembered authentication"):
          agent(m, "--answer alice-pw --requests 1", "/tmp/agent2")
          one = f"check org.freedesktop.timedate1.set-time {clock()} 1"
          two = f"check org.freedesktop.timedate1.set-time {clock()} 0"
          out, _ = tty(m, f"script -qec {shlex.quote(one + '; ' + two + '; :')} /dev/null")
          assert out.count('"allow"') == 2, out
          requests = [e for e in events(m, "/tmp/agent2") if e["event"] == "request"]
          assert len(requests) == 1, requests
          # Not for a process outside that terminal.
          out, _ = tty(m, two)
          assert '"challenge"' in out, out

      with subtest("dismissing denies"):
          agent(m, "--dismiss --requests 1", "/tmp/agent3")
          out, _ = tty(m, "check org.freedesktop.timedate1.set-ntp 'systemd::Clock::\"ntp\"' 1")
          assert '"deny"' in out, out
          assert any(e["event"] == "dismissed" for e in events(m, "/tmp/agent3"))

      with subtest("the agent is told when the caller gives up"):
          stop_agents(m)
          background(m, "sleep 60 | cedarkit-cli-agent --stdin --requests 1", "/tmp/agent4")
          m.wait_until_succeeds("grep -q registered /tmp/agent4")
          tty(m, "check org.freedesktop.timedate1.set-ntp 'systemd::Clock::\"ntp\"' 1 2")
          m.wait_until_succeeds("grep -q cancelled /tmp/agent4")

      with subtest("only one agent per session"):
          stop_agents(m)
          background(m, "sleep 60 | cedarkit-cli-agent --stdin", "/tmp/agent5")
          m.wait_until_succeeds("grep -q registered /tmp/agent5")
          out, status = tty(m, "cedarkit-cli-agent")
          assert status != 0 and "another agent" in out, out
    '';
  };

  # polkit's interface, with polkit's own client tools.
  polkit = test "cedarkit-polkit" {
    nodes.machine = {
      imports = [
        base
        polkitMode
      ];
    };
    testScript = ''
      m = machine
      login(m)
      m.succeed("busctl status org.freedesktop.PolicyKit1 | grep -q cedarkitd")

      with subtest("pkaction lists the actions"):
          assert int(m.succeed("pkaction | wc -l")) == 158
          out = m.succeed("pkaction --action-id org.freedesktop.login1.reboot --verbose")
          assert "implicit active:   yes" in out and "reboot the system" in out, out

      with subtest("pkcheck"):
          _, status = tty(m, "pkcheck --process $$ --action-id org.freedesktop.login1.reboot")
          assert status == 0
          # alice is the only admin, so it's her own password: auth_self_keep.
          out, status = tty(m, "pkcheck --process $$ --action-id org.freedesktop.timedate1.set-time")
          assert status == 2 and "auth_self_keep" in out, out
          # For bob, it's an admin's.
          status, out = outside(m, "bob", "pkcheck --process $$ --action-id org.freedesktop.timedate1.set-time")
          assert status == 2 and "auth_admin_keep" in out, out
          # Resources from details: the machine's owner may open a shell.
          _, status = tty(m, "pkcheck --process $$ --action-id org.freedesktop.machine1.shell "
                             "--detail machine box --detail owner_uid $(id -u)")
          assert status == 0
          # Undeclared actions, and details that don't say what's acted on.
          _, status = tty(m, "pkcheck --process $$ --action-id org.example.nope")
          assert status == 1
          _, status = tty(m, "pkcheck --process $$ --action-id org.freedesktop.machine1.shell")
          assert status == 1

      with subtest("only trusted callers may check for other users"):
          status, out = outside(m, "bob", "pkcheck --process 1 --action-id org.freedesktop.login1.reboot")
          assert status != 0 and "trusted callers" in out, out
    '';
  };

  # polkit's textual agent and its helper, which runs PAM and reports to
  # org.freedesktop.PolicyKit1: cedarkitd.
  polkit-agent = test "cedarkit-polkit-agent" {
    nodes.machine = {
      imports = [
        base
        polkitMode
      ];
    };
    testScript = ''
      m = machine
      login(m)

      with subtest("authenticating through polkit's agent"):
          n = start(m, "pkcheck --enable-internal-agent -u --process $$ --action-id org.freedesktop.timedate1.set-time")
          m.wait_until_tty_matches("1", "Password:")
          m.send_chars("alice-pw\n")
          out, status = result(m, n)
          assert status == 0 and "temporary_authorization_id" in out, out

      with subtest("the temporary authorization"):
          out, status = tty(m, "pkcheck --process $$ --action-id org.freedesktop.timedate1.set-time")
          assert status == 0 and "temporary_authorization_id" in out, out
          out, _ = tty(m, "pkcheck --list-temp")
          assert "org.freedesktop.timedate1.set-time" in out, out
          tty(m, "pkcheck --revoke-temp")
          _, status = tty(m, "pkcheck --process $$ --action-id org.freedesktop.timedate1.set-time")
          assert status == 2
    '';
  };

  # The scenario of polkit's btime bug: run0 twice, as soon as a terminal
  # opens. The second shares the first's temporary authorization.
  run0 = test "cedarkit-run0" {
    nodes.machine = {
      imports = [
        base
        polkitMode
      ];
    };
    testScript = ''
      m = machine
      login(m)
      # The marker is computed, so that the echoed command can't match it.
      m.send_chars("script -qec 'run0 true && run0 true && echo both-ran-$((1+1)); :' /tmp/typescript; echo $? > /tmp/run0.rc\n")
      m.wait_until_tty_matches("1", "Password:")
      m.send_chars("alice-pw\n")
      # A second prompt would leave this waiting.
      m.wait_for_file("/tmp/run0.rc", timeout=60)
      assert "both-ran-2" in m.succeed("cat /tmp/typescript"), m.succeed("cat /tmp/typescript")
      journal = m.succeed("journalctl -u cedarkitd")
      assert journal.count("remembering the authentication") == 1, journal
      allowed = [l for l in journal.splitlines() if "systemd1.manage-units" in l and 'resource=systemd::Unit::"run-' in l and 'decision="allow"' in l]
      assert len(allowed) == 2, journal
    '';
  };

  # Stock systemd passes few of the details resources are built from.
  unpatched-systemd = test "cedarkit-unpatched-systemd" {
    nodes.strict = {
      imports = [
        base
        polkitMode
      ];
    };
    nodes.fallback = {
      imports = [
        base
        polkitMode
      ];
      services.cedarkit.fillMissingDetails = true;
    };
    testScript = ''
      for m in [strict, fallback]:
          login(m)

      with subtest("singletons need no details"):
          for m in [strict, fallback]:
              agent(m, "--answer alice-pw --requests 1", "/tmp/agent")
              _, status = tty(m, "timedatectl set-timezone Europe/Berlin")
              assert status == 0
              assert "Europe/Berlin" in m.succeed("timedatectl show -p Timezone")

      with subtest("without the details, only the fallback can decide"):
          # hostnamed doesn't say which machine-info key it's setting.
          agent(strict, "--answer alice-pw --requests 1", "/tmp/agent2")
          _, status = tty(strict, "hostnamectl icon-name strict-icon")
          assert status != 0
          strict.succeed("journalctl -u cedarkitd | grep -q \"don't say which resource\"")
          assert not any(e["event"] == "request" for e in events(strict, "/tmp/agent2"))

          agent(fallback, "--answer alice-pw --requests 1", "/tmp/agent2")
          # Authorized; hostnamed then can't write /etc/machine-info in
          # this VM, which is beside the point.
          tty(fallback, "hostnamectl icon-name fallback-icon")
          assert any(e["event"] == "result" and e["success"] for e in events(fallback, "/tmp/agent2"))
          fallback.succeed("journalctl -u cedarkitd | grep 'set-machine-info' | grep -q 'decision=\"allow\"'")

      with subtest("users can't be made up: lingering needs the patch"):
          _, status = tty(fallback, "loginctl enable-linger")
          assert status != 0
    '';
  };

  # The GTK agent, in a headless Wayland session.
  gtk-agent = test "cedarkit-gtk-agent" {
    nodes.machine =
      { pkgs, ... }:
      {
        imports = [ base ];
        programs.sway.enable = true;
        environment.systemPackages = [
          pkgs.grim
          pkgs.wtype
        ];
        environment.etc."sway-test.conf".text = ''
          exec env RUST_LOG=cedarkit_agent=info cedarkit-agent > /tmp/gtk-agent.log 2>&1
        '';
        virtualisation.memorySize = 2048;
      };
    testScript = ''
      m = machine
      login(m)
      m.send_chars("WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman "
                   "sway -c /etc/sway-test.conf >/tmp/sway.log 2>&1 &\n")
      m.wait_until_succeeds("journalctl -u cedarkitd | grep -q 'agent registered'", timeout=120)
      socket = m.succeed("ls /run/user/1000 | grep -x 'wayland-[0-9]*' | head -1").strip()
      wayland = f"WAYLAND_DISPLAY={socket} XDG_RUNTIME_DIR=/run/user/1000"

      n = start(m, f"check org.freedesktop.timedate1.set-time {clock()} 1")
      m.wait_until_succeeds(f"su alice -c '{wayland} grim /tmp/before.png'")
      m.sleep(3)
      m.succeed(f"su alice -c '{wayland} grim /tmp/dialog.png'")
      m.copy_from_machine("/tmp/dialog.png")
      # wtype can lose keys while the virtual keyboard settles, so prime it,
      # and retype after a failure, as the dialog then asks again.
      for attempt in range(3):
          m.succeed(f"su alice -c '{wayland} wtype -k Shift_L'")
          m.sleep(1)
          m.succeed(f"su alice -c '{wayland} wtype -d 50 -k Shift_L alice-pw -k Return'")
          try:
              m.wait_until_succeeds(f"test -f /tmp/rc{n}", timeout=20)
              break
          except Exception:
              continue
      out, _ = result(m, n)
      assert '"allow"' in out, out
      m.succeed("grep -q authenticated /tmp/gtk-agent.log")
    '';
  };
}
