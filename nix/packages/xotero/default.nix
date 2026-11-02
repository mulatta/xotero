{
  lib,
  rustPlatform,
  cacert,
  zotero-schema,
}:

rustPlatform.buildRustPackage {
  pname = "xotero";
  version = "0.1.0";

  src = ../../..;
  cargoLock.lockFile = ../../../Cargo.lock;

  buildAndTestSubdir = "xotero";

  # Embedded at compile time so the served schema always matches the binary.
  XOTERO_SCHEMA = "${zotero-schema}/schema.json";

  preCheck = ''
    export SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
  '';

  meta = {
    description = "Self-hosted Zotero Web API v3 sync server";
    mainProgram = "xotero";
    license = lib.licenses.mit;
    platforms = lib.platforms.unix;
    maintainers = [ lib.maintainers.mulatta ];
  };
}
