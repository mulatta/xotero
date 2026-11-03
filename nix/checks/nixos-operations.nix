{ pkgs, self }:

let
  testPkgs = pkgs.extend self.overlays.default;
  v13Migrations = import ./v13-migrations.nix { pkgs = testPkgs; };
in
testPkgs.testers.runNixOSTest {
  name = "xotero-operations";

  nodes.machine = {
    imports = [
      self.nixosModules.xotero
      (import ./aws-client.nix { pkgs = testPkgs; })
    ];

    services.xotero = {
      enable = true;
      bind = "127.0.0.1:8189";
      publicUrl = "http://localhost:8189";
      keys.recovery.file = testPkgs.writeText "xotero-recovery-key" "recoverytoken";
      bootstrapOidcIssuer = "https://id.example.test";
      bootstrapOidcSubject = "alice-subject";
      loginKdfKeyFile = testPkgs.writeText "xotero-login-kdf-key" "0123456789abcdef0123456789abcdef";
      s3 = {
        endpoint = "http://127.0.0.1:9000";
        region = "us-east-1";
        bucket = "zotero";
        accessKeyFile = testPkgs.writeText "xotero-s3-access" "rustfsadmin";
        secretKeyFile = testPkgs.writeText "xotero-s3-secret" "rustfsadmin";
      };
    };

    services.rustfs = {
      enable = true;
      package = import ./rustfs.nix { pkgs = testPkgs; };
      environmentFile = toString (
        testPkgs.writeText "rustfs-secrets.env" ''
          RUSTFS_ACCESS_KEY=rustfsadmin
          RUSTFS_SECRET_KEY=rustfsadmin
        ''
      );
    };

    # The test script orders migrate-only runs, unit starts, and DB rebuilds.
    systemd.services.xotero.wantedBy = testPkgs.lib.mkForce [ ];
    systemd.services.xotero.environment = {
      XOTERO_USER_ID = testPkgs.lib.mkForce "101";
      XOTERO_USERNAME = testPkgs.lib.mkForce "alice";
      XOTERO_DISPLAY_NAME = testPkgs.lib.mkForce "Alice";
    };

    environment.etc."xotero-test/v13-migrations".source = v13Migrations;
    environment.etc."xotero-test/current-migrations".source = ../../xotero/migrations;
    environment.systemPackages = [
      testPkgs.curl
      testPkgs.jq
      testPkgs.postgresql
      testPkgs.sqlx-cli
      testPkgs.xotero
    ];
  };

  testScript = builtins.readFile ../../checks/operations-test.py;
}
