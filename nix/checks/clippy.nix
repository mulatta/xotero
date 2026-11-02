{ pkgs }:

# Reuse the package's vendored dependencies so lints run offline in the sandbox.
(pkgs.callPackage ../packages/xotero { }).overrideAttrs (old: {
  pname = "xotero-clippy";
  nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
  buildPhase = ''
    runHook preBuild
    cargo clippy --offline --all-targets --all-features -- -D warnings
    runHook postBuild
  '';
  doCheck = false;
  installPhase = "touch $out";
})
