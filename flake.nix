{
  description = "xotero";

  inputs = {
    # keep-sorted start
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    # keep-sorted end
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      inherit (nixpkgs) lib;

      eachSystem =
        f:
        lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = nixpkgs.legacyPackages.${system};
          }
        );

      treefmtEval = eachSystem (
        { pkgs, ... }:
        treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs = {
            deadnix.enable = true;
            keep-sorted.enable = true;
            nixfmt.enable = true;
            rustfmt = {
              enable = true;
              edition = "2021";
            };
            statix.enable = true;
          };
        }
      );
    in
    {
      overlays.default = final: prev: {
        xotero = prev.callPackage ./nix/packages/xotero { inherit (final) zotero-schema; };
        zotero-schema = prev.callPackage ./nix/packages/zotero-schema { };
      };

      nixosModules.xotero = ./nix/modules/nixos/xotero.nix;
      nixosModules.default = ./nix/modules/nixos/xotero.nix;

      packages = eachSystem (
        { pkgs, ... }:
        let
          zotero-schema = pkgs.callPackage ./nix/packages/zotero-schema { };
        in
        {
          inherit zotero-schema;
          xotero = pkgs.callPackage ./nix/packages/xotero { inherit zotero-schema; };
        }
      );

      checks = eachSystem (
        { system, pkgs, ... }:
        {
          api-contracts = import ./nix/checks/api-contracts.nix { inherit pkgs; };
          clippy = import ./nix/checks/clippy.nix { inherit pkgs; };
          formatting = treefmtEval.${system}.config.build.check self;
        }
        # nixosTest needs a linux VM, so wire it only on linux systems.
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          nixos-admin = import ./nix/checks/nixos-admin.nix { inherit pkgs self; };
          nixos-key-auth = import ./nix/checks/nixos-key-auth.nix { inherit pkgs self; };
          nixos-sync = import ./nix/checks/nixos-sync.nix { inherit pkgs self; };
        }
      );

      formatter = eachSystem ({ system, ... }: treefmtEval.${system}.config.build.wrapper);

      devShells = eachSystem (
        { pkgs, ... }:
        {
          default = pkgs.mkShell {
            # The server embeds the pinned schema at compile time.
            XOTERO_SCHEMA = "${pkgs.callPackage ./nix/packages/zotero-schema { }}/schema.json";
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.rustfmt
              pkgs.clippy
              pkgs.postgresql_16
              pkgs.sqlx-cli
            ];
          };
        }
      );
    };
}
