{
  lib,
  buildNpmPackage,
  fetchFromGitHub,
  nodejs_22,
}:

let
  inventory = (lib.importJSON ../../../checks/contracts/web-api.json).sources.EXPORT;

  # The upstream submodules, fetched one by one: translate carries a nested
  # utilities submodule that the server never loads.
  gitlinks = {
    "modules/translate" = fetchFromGitHub {
      owner = "zotero";
      repo = "translate";
      rev = "e0fe482b8a07e42cbf83545947382008ae7ddb82";
      hash = "sha256-K3KeJNw9CnkAlEC4b/pv0FTobXNTUJyZnLSOBk9q90E=";
    };
    "modules/translators" = fetchFromGitHub {
      owner = "zotero";
      repo = "translators";
      rev = "424cfbe720650d51f710f4d9cbf9f4118673c719";
      hash = "sha256-m6ENezjcEB8A1B3xKt5EJAkFh01nWYbuhlAm1w6WX10=";
    };
    "modules/utilities" = fetchFromGitHub {
      owner = "zotero";
      repo = "utilities";
      rev = "1dd38e27edf81e9d9c4161c957b7efb7f5681ac3";
      hash = "sha256-hTKQHLHtSnIy9+tYg9OT9s5l3r/g17gzRZUymnsqxBI=";
    };
    "modules/zotero-schema" = fetchFromGitHub {
      owner = "zotero";
      repo = "zotero-schema";
      rev = "70c3aa98627413d6a30dca955886eafbde085ce9";
      hash = "sha256-M6+HHdFwuDS19U3d9xu8QcQoZPtmWKgN/aWh45q9chQ=";
    };
  };

  rev = "672d4f3b6254c3afd4d62cdeef5aed7602d84078";
  version = "2.0.5";

  sourceChecks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (
      key: sha: "echo '${sha}  ${lib.removePrefix "source-sha256:" key}' | sha256sum -c -"
    ) (lib.filterAttrs (key: _: lib.hasPrefix "source-sha256:" key) inventory.integrity)
  );
in

assert lib.assertMsg
  (
    rev == inventory.revision
    && version == inventory.version
    && lib.mapAttrs (_: s: s.rev) gitlinks == inventory.gitlinks
  )
  "translation-server pin drifted from checks/contracts/web-api.json (revision, version or gitlinks differ)";

buildNpmPackage {
  pname = "translation-server";
  inherit version;
  __structuredAttrs = true;

  src = fetchFromGitHub {
    owner = "zotero";
    repo = "translation-server";
    inherit rev;
    fetchSubmodules = false;
    hash = "sha256-Etd8zai8LvYcbFo509PvVENsmoYOEwRYSqped407w2Y=";
  };

  nodejs = nodejs_22;

  npmDepsHash = "sha256-yFL4n3DduhVizxnjbEA8kupR35wODJMDtodGOmqH9L4=";
  # npm install creates _cacache/tmp, so the fetched cache must be writable.
  makeCacheWritable = true;
  dontNpmBuild = true;

  # Fail before anything is installed if a pinned file drifted from the
  # contract inventory.
  postPatch = ''
    echo '${inventory.lock_sha256}  package-lock.json' | sha256sum -c -
    ${sourceChecks}
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (path: src: ''
        rm -rf ${path}
        cp -r ${src} ${path}
        chmod -R u+w ${path}
      '') gitlinks
    )}
  '';

  # node-config resolves ./config from the CWD; bind to loopback unless the
  # deployer sets NODE_CONFIG.
  postInstall = ''
    mkdir -p $out/bin
    makeWrapper ${lib.getExe nodejs_22} $out/bin/translation-server \
      --add-flags $out/lib/node_modules/translation-server/src/server.js \
      --set NODE_CONFIG_DIR $out/lib/node_modules/translation-server/config \
      --set-default NODE_CONFIG '{"host":"127.0.0.1"}'
  '';

  doCheck = false;

  passthru.gitlinks = gitlinks;

  meta = {
    description = "Zotero translation-server pinned to the revision the contract inventory records";
    homepage = "https://github.com/zotero/translation-server";
    license = lib.licenses.agpl3Only;
    mainProgram = "translation-server";
    platforms = lib.platforms.all;
  };
}
