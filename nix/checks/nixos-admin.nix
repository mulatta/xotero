{ pkgs, self }:

let
  testPkgs = pkgs.extend self.overlays.default;
  migrationsThrough =
    version:
    testPkgs.linkFarm "xotero-${version}-migrations" (
      map
        (name: {
          inherit name;
          path = ../../xotero/migrations + "/${name}";
        })
        (
          builtins.filter (name: builtins.substring 0 4 name <= version) (
            builtins.attrNames (builtins.readDir ../../xotero/migrations)
          )
        )
    );
  v15Migrations = migrationsThrough "0015";
  v16Migrations = migrationsThrough "0016";
  v18Migrations = migrationsThrough "0018";
  v19Migrations = migrationsThrough "0019";
  v20Migrations = migrationsThrough "0020";
in
testPkgs.testers.runNixOSTest {
  name = "xotero-admin";
  nodes.machine = {
    imports = [ self.nixosModules.xotero ];
    services.xotero = {
      enable = true;
      publicUrl = "http://localhost:8189";
      bootstrapOidcIssuer = "https://id.example.test";
      bootstrapOidcSubject = "owner";
      loginKdfKeyFile = testPkgs.writeText "admin-kdf" "0123456789abcdef0123456789abcdef";
      s3 = {
        endpoint = "http://127.0.0.1:9000";
        accessKeyFile = testPkgs.writeText "admin-s3-access" "rustfsadmin";
        secretKeyFile = testPkgs.writeText "admin-s3-secret" "rustfsadmin";
      };
    };
    systemd.services.xotero.wantedBy = testPkgs.lib.mkForce [ ];
    services.postgresql.authentication = testPkgs.lib.mkAfter ''
      host all all 127.0.0.1/32 trust
    '';
    services.rustfs = {
      enable = true;
      package = import ./rustfs.nix { pkgs = testPkgs; };
      environmentFile = toString (
        testPkgs.writeText "admin-rustfs.env" ''
          RUSTFS_ACCESS_KEY=rustfsadmin
          RUSTFS_SECRET_KEY=rustfsadmin
        ''
      );
    };
    environment.etc."xotero-test/v15-migrations".source = v15Migrations;
    environment.etc."xotero-test/v16-migrations".source = v16Migrations;
    environment.etc."xotero-test/v18-migrations".source = v18Migrations;
    environment.etc."xotero-test/v19-migrations".source = v19Migrations;
    environment.etc."xotero-test/v20-migrations".source = v20Migrations;
    environment.etc."xotero-test/current-migrations".source = ../../xotero/migrations;
    environment.etc."xotero-test/kdf".text = "0123456789abcdef0123456789abcdef";
    environment.etc."xotero-test/recovery-key".text = "fixture-recovery";
    environment.etc."xotero-test/admin-recovery-key".text = "fixture-admin-recovery";
    environment.systemPackages = [
      testPkgs.xotero
      testPkgs.sqlx-cli
      testPkgs.postgresql
      testPkgs.chromium
      testPkgs.openssl
      (testPkgs.python3.withPackages (ps: [
        ps.psycopg
        ps.playwright
      ]))
    ];
  };
  testScript = builtins.readFile ../../checks/admin-test.py;
}
