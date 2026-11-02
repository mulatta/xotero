{
  lib,
  stdenvNoCC,
  fetchFromGitHub,
  jq,
}:

# zotero-schema publishes no releases, so the pin follows a Web Library
# release: serve the exact schema commit that release vendors as its
# modules/zotero-schema submodule, which is what that client expects.
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "zotero-schema";
  version = "0-unstable-web-library-${finalAttrs.passthru.webLibraryVersion}";

  src = fetchFromGitHub {
    owner = "zotero";
    repo = "zotero-schema";
    rev = "b86c79b56479cadac3288e1f122cf34ef04e8809";
    hash = "sha256-sdFeoorYP8oSP2NRhMijL7gOFgW7RCnSQo+tMHIcNvc=";
  };

  nativeBuildInputs = [ jq ];

  # Fail the build rather than ship a file the server cannot parse.
  installPhase = ''
    runHook preInstall
    jq -e '.version | numbers' schema.json > /dev/null
    install -Dm444 schema.json $out/schema.json
    runHook postInstall
  '';

  passthru.webLibraryVersion = "1.8.3";

  meta = {
    description = "Zotero data schema pinned to the commit Web Library ${finalAttrs.passthru.webLibraryVersion} vendors";
    homepage = "https://github.com/zotero/zotero-schema";
    platforms = lib.platforms.all;
  };
})
