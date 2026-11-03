{ pkgs, self }:

let
  testPkgs = pkgs.extend self.overlays.default;
  legacyMigrations = testPkgs.linkFarm "xotero-v7-migrations" (
    map
      (path: {
        name = builtins.baseNameOf path;
        inherit path;
      })
      [
        ../../../xotero/migrations/0001_init.sql
        ../../../xotero/migrations/0002_files.sql
        ../../../xotero/migrations/0003_fulltext.sql
        ../../../xotero/migrations/0004_fulltext_search.sql
        ../../../xotero/migrations/0005_item_search.sql
        ../../../xotero/migrations/0006_item_columns.sql
        ../../../xotero/migrations/0007_item_columns_fixes.sql
      ]
  );
  v13Migrations = import ../v13-migrations.nix { pkgs = testPkgs; };
in
testPkgs.testers.runNixOSTest {
  name = "xotero-key-auth";

  nodes.machine = {
    imports = [
      self.nixosModules.xotero
      (import ../aws-client.nix { pkgs = testPkgs; })
    ];

    services.xotero = {
      enable = true;
      bind = "127.0.0.1:8189";
      publicUrl = "http://localhost:8189";
      keys.recovery.file = testPkgs.writeText "xotero-recovery-key" "recoverytoken";
      keys.readonly = {
        file = testPkgs.writeText "xotero-readonly-recovery-key" "recoveryreadonly";
        readOnly = true;
      };
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
      package = import ../rustfs.nix { pkgs = testPkgs; };
      environmentFile = toString (
        testPkgs.writeText "rustfs-secrets.env" ''
          RUSTFS_ACCESS_KEY=rustfsadmin
          RUSTFS_SECRET_KEY=rustfsadmin
        ''
      );
    };

    # Keep xotero stopped until the test has recreated a populated v7 database.
    systemd.services.xotero.wantedBy = testPkgs.lib.mkForce [ ];
    systemd.services.xotero.environment = {
      XOTERO_USER_ID = testPkgs.lib.mkForce "101";
      XOTERO_USERNAME = testPkgs.lib.mkForce "alice";
      XOTERO_DISPLAY_NAME = testPkgs.lib.mkForce "Alice";
    };

    environment.etc."xotero-test/migrations".source = legacyMigrations;
    environment.etc."xotero-test/v13-migrations".source = v13Migrations;
    environment.etc."xotero-test/current-migrations".source = ../../../xotero/migrations;
    environment.systemPackages = [
      testPkgs.curl
      testPkgs.jq
      testPkgs.postgresql
      testPkgs.python3
      testPkgs.sqlx-cli
      testPkgs.xotero
    ];
  };

  nodes.keyless = {
    imports = [ self.nixosModules.xotero ];
    services.xotero = {
      enable = true;
      bind = "127.0.0.1:8189";
      publicUrl = "http://localhost:8189";
      bootstrapOidcIssuer = "https://id.example.test";
      bootstrapOidcSubject = "alice-subject";
      loginKdfKeyFile = testPkgs.writeText "xotero-keyless-kdf" "0123456789abcdef0123456789abcdef";
      s3 = {
        endpoint = "http://127.0.0.1:9000";
        accessKeyFile = testPkgs.writeText "xotero-keyless-s3-access" "rustfsadmin";
        secretKeyFile = testPkgs.writeText "xotero-keyless-s3-secret" "rustfsadmin";
      };
    };
    environment.systemPackages = [
      testPkgs.curl
      testPkgs.python3
    ];
  };

  testScript = builtins.readFile ./test.py;
}
