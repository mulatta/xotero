{ pkgs, self }:

# Headless VM running only the xotero server + postgres (no Zotero / no desktop);
# the test driver exercises the sync API directly over HTTP. The overlay is
# applied to the host pkgs (the VM inherits it read-only) rather than set on the
# node, which runNixOSTest forbids.
let
  testPkgs = pkgs.extend self.overlays.default;
in
testPkgs.testers.runNixOSTest {
  name = "xotero-sync";

  nodes.machine = {
    imports = [ self.nixosModules.xotero ];

    services.xotero = {
      enable = true;
      bind = "127.0.0.1:8189";
      publicUrl = "http://localhost:8189";
      keys = {
        app.file = testPkgs.writeText "xotero-app-key" "testtoken";
        cli = {
          file = testPkgs.writeText "xotero-cli-key" "readonlytoken";
          readOnly = true;
        };
      };
      bootstrapOidcIssuer = "https://id.example.test";
      bootstrapOidcSubject = "owner-subject";
      loginKdfKeyFile = testPkgs.writeText "xotero-login-kdf-key" "0123456789abcdef0123456789abcdef";
      # Attachment bytes go to the local RustFS standing in for S3/R2.
      s3 = {
        endpoint = "http://127.0.0.1:9000";
        region = "us-east-1";
        bucket = "zotero";
        accessKeyFile = testPkgs.writeText "xotero-s3-access" "rustfsadmin";
        secretKeyFile = testPkgs.writeText "xotero-s3-secret" "rustfsadmin";
      };
    };

    # RustFS: an S3-compatible store for the attachment upload/download paths.
    # Share the pinned provider compatibility correction across service checks.
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
    systemd.services.xotero.after = [ "rustfs.service" ];
    services.postgresql.settings = {
      log_lock_waits = true;
      deadlock_timeout = "10ms";
    };
    environment.etc."xotero-checkpoint9-migrations".source = ../../xotero/migrations;

    environment.systemPackages = [
      testPkgs.curl
      testPkgs.jq
      testPkgs.gzip
      testPkgs.postgresql
      (testPkgs.python3.withPackages (ps: [ ps.psycopg ]))
      testPkgs.unzip
      testPkgs.zip
      # `mc` creates the bucket before the upload subtest.
      testPkgs.minio-client
    ];
  };

  testScript = builtins.readFile ../../checks/sync-test.py;
}
