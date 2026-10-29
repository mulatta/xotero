{ pkgs, self }:

let
  testPkgs = pkgs.extend self.overlays.default;
  v15Migrations = testPkgs.linkFarm "xotero-v15-migrations" (
    map
      (name: {
        inherit name;
        path = ../../xotero/migrations + "/${name}";
      })
      (
        builtins.filter (name: builtins.substring 0 4 name <= "0015") (
          builtins.attrNames (builtins.readDir ../../xotero/migrations)
        )
      )
  );
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
    environment.etc."xotero-test/current-migrations".source = ../../xotero/migrations;
    environment.etc."xotero-test/kdf".text = "0123456789abcdef0123456789abcdef";
    environment.systemPackages = [
      testPkgs.xotero
      testPkgs.sqlx-cli
      testPkgs.postgresql
      (testPkgs.python3.withPackages (ps: [ ps.psycopg ]))
    ];
  };
  testScript = builtins.readFile ../../checks/admin-test.py;
}
