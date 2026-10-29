{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.xotero;

  # Fold the apiKeyFile shorthand into the keys set.
  allKeys =
    cfg.keys
    // lib.optionalAttrs (cfg.apiKeyFile != null) {
      default = {
        file = cfg.apiKeyFile;
        readOnly = false;
      };
    };
  credName = name: "key-${name}";
  # XOTERO_KEYS: "<role>:%d/<cred>" entries; %d is the systemd credentials dir.
  keyManifest = lib.concatStringsSep "," (
    lib.mapAttrsToList (name: k: "${if k.readOnly then "ro" else "rw"}:%d/${credName name}") allKeys
  );
in
{
  options.services.xotero = {
    enable = lib.mkEnableOption "self-hosted Zotero sync server";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.xotero;
      defaultText = lib.literalExpression "pkgs.xotero";
      description = "The xotero package (from xotero's overlay).";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "xotero";
      description = "User the service runs as, and the PostgreSQL role (peer auth).";
    };

    bind = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8189";
      description = "Internal listen address; front it with a reverse proxy.";
    };

    bootstrapUserId = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = "Stable local user ID owning the legacy personal library.";
    };

    bootstrapInstanceAdmin = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Explicitly create the first enabled OIDC instance administrator once.
        Durable completion prevents role or identity repair on later starts,
        even when this option remains enabled.
      '';
    };

    bootstrapUsername = lib.mkOption {
      type = lib.types.str;
      default = "xotero";
      description = "Initial username for the bootstrap personal-library owner.";
    };

    bootstrapDisplayName = lib.mkOption {
      type = lib.types.str;
      default = "xotero";
      description = "Display name for the bootstrap personal-library owner.";
    };

    publicUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://zotero.example.org";
      description = ''
        Client-facing base URL (the reverse-proxy address). Used for the login,
        upload and download URLs handed to the client. No trailing slash.
      '';
    };

    database = lib.mkOption {
      type = lib.types.str;
      default = "postgres:///xotero?host=/run/postgresql";
      description = "PostgreSQL connection URL (defaults to the local peer socket).";
    };

    bootstrapOidcIssuer = lib.mkOption {
      type = lib.types.str;
      example = "https://id.example.org";
      description = ''
        Stable OIDC issuer for the bootstrap user's external identity. Reverse
        proxy must overwrite `X-Xotero-OIDC-Issuer` from its verified claim.
        Used only for initial setup; later starts never repair removed mappings.
      '';
    };

    bootstrapOidcSubject = lib.mkOption {
      type = lib.types.str;
      example = "248289761001";
      description = ''
        Stable OIDC subject for the bootstrap user's external identity. Reverse
        proxy must overwrite `X-Xotero-OIDC-Subject` from its verified claim.
      '';
    };

    loginKdfKeyFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        File containing at least 32 bytes of stable secret material used only to
        derive browser-login API keys. All replicas must use the same value.
        Loaded as a systemd credential.
      '';
    };

    uploadConcurrency = lib.mkOption {
      type = lib.types.ints.positive;
      default = 4;
      description = "Maximum admitted attachment uploads before reading request bodies.";
    };
    uploadParts = lib.mkOption {
      type = lib.types.ints.positive;
      default = 2;
      description = "Maximum concurrent SDK multipart parts per attachment upload.";
    };
    uploadMaxBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 256 * 1024 * 1024;
      description = "Maximum encoded and decoded attachment upload size in bytes.";
    };
    uploadTimeout = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = "Total attachment upload deadline in seconds, including admission.";
    };
    s3 = lib.mkOption {
      description = "S3-compatible object storage for attachment bytes (e.g. Cloudflare R2).";
      type = lib.types.submodule {
        options = {
          endpoint = lib.mkOption {
            type = lib.types.str;
            example = "https://<account>.r2.cloudflarestorage.com";
            description = "S3 endpoint URL.";
          };
          region = lib.mkOption {
            type = lib.types.str;
            default = "auto";
            description = "S3 region (R2 ignores it).";
          };
          bucket = lib.mkOption {
            type = lib.types.str;
            default = "zotero";
            description = "Bucket holding the attachment objects.";
          };
          accessKeyFile = lib.mkOption {
            type = lib.types.path;
            description = "File with the S3 access key ID (a secret), loaded as a credential.";
          };
          secretKeyFile = lib.mkOption {
            type = lib.types.path;
            description = "File with the S3 secret access key (a secret), loaded as a credential.";
          };
          pathStyle = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = "Path-style addressing (required by RustFS/MinIO; R2 accepts it).";
          };
          presignTtl = lib.mkOption {
            type = lib.types.ints.positive;
            default = 120;
            description = ''
              Lifetime (seconds) of a pre-signed download URL. Kept short: the
              client follows the redirect immediately, and the URL is an
              unauthenticated capability.
            '';
          };
        };
      };
    };

    keys = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            file = lib.mkOption {
              type = lib.types.path;
              description = "File holding this key's single-line token (e.g. a sops-nix secret).";
            };
            readOnly = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Reject writes for this key (reads still work).";
            };
          };
        }
      );
      default = { };
      example = lib.literalExpression ''
        {
          app.file = config.sops.secrets.xotero-app-key.path;
          cli = {
            file = config.sops.secrets.xotero-cli-key.path;
            readOnly = true;
          };
        }
      '';
      description = ''
        Optional named recovery API keys, each loaded from a secret file
        as a systemd credential and retained only as a digest. Browser login mints separate
        database-owned keys and never returns these static credentials.
      '';
    };

    apiKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Shorthand for a single read/write key (equivalent to one `keys` entry).
        Use `keys` instead when you also need a read-only key. Loaded as a systemd
        credential, never placed in the store.
      '';
    };

    createLocalDatabase = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Provision the database/role on the local PostgreSQL.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.apiKeyFile == null || !(cfg.keys ? default);
        message = "services.xotero: apiKeyFile conflicts with keys.default.";
      }
      {
        assertion = cfg.bootstrapOidcIssuer != "";
        message = "services.xotero.bootstrapOidcIssuer must be nonempty.";
      }
      {
        assertion = cfg.bootstrapOidcSubject != "";
        message = "services.xotero.bootstrapOidcSubject must be nonempty.";
      }
      {
        assertion = lib.hasPrefix "127." cfg.bind || lib.hasPrefix "[::1]:" cfg.bind;
        message = "services.xotero.bind must be loopback so only a trusted local proxy can set OIDC headers.";
      }
    ];

    services.postgresql = lib.mkIf cfg.createLocalDatabase {
      enable = true;
      ensureDatabases = [ "xotero" ];
      ensureUsers = [
        {
          name = cfg.user;
          ensureDBOwnership = true;
        }
      ];
    };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
    };
    users.groups.${cfg.user} = { };

    systemd.services.xotero = {
      description = "Self-hosted Zotero sync server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ] ++ lib.optional cfg.createLocalDatabase "postgresql.service";
      requires = lib.optional cfg.createLocalDatabase "postgresql.service";

      environment = {
        XOTERO_BIND = cfg.bind;
        XOTERO_PUBLIC_URL = cfg.publicUrl;
        XOTERO_DATABASE_URL = cfg.database;
        XOTERO_USER_ID = toString cfg.bootstrapUserId;
        XOTERO_USERNAME = cfg.bootstrapUsername;
        XOTERO_DISPLAY_NAME = cfg.bootstrapDisplayName;
        XOTERO_BOOTSTRAP_INSTANCE_ADMIN = lib.boolToString cfg.bootstrapInstanceAdmin;
        XOTERO_BOOTSTRAP_OIDC_ISSUER = cfg.bootstrapOidcIssuer;
        XOTERO_BOOTSTRAP_OIDC_SUBJECT = cfg.bootstrapOidcSubject;
        XOTERO_S3_ENDPOINT = cfg.s3.endpoint;
        XOTERO_S3_REGION = cfg.s3.region;
        XOTERO_S3_BUCKET = cfg.s3.bucket;
        XOTERO_S3_PATH_STYLE = lib.boolToString cfg.s3.pathStyle;
        XOTERO_S3_PRESIGN_TTL = toString cfg.s3.presignTtl;
        XOTERO_UPLOAD_CONCURRENCY = toString cfg.uploadConcurrency;
        XOTERO_UPLOAD_PARTS = toString cfg.uploadParts;
        XOTERO_UPLOAD_MAX_BYTES = toString cfg.uploadMaxBytes;
        XOTERO_UPLOAD_TIMEOUT = toString cfg.uploadTimeout;
        # %d expands to the systemd credentials directory at runtime.
        XOTERO_S3_ACCESS_KEY_FILE = "%d/s3-access-key";
        XOTERO_S3_SECRET_KEY_FILE = "%d/s3-secret-key";
        XOTERO_LOGIN_KDF_KEY_FILE = "%d/login-kdf-key";
        RUST_LOG = "info";
      }
      // lib.optionalAttrs (allKeys != { }) {
        XOTERO_KEYS = keyManifest;
      };

      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        User = cfg.user;
        Group = cfg.user;
        LoadCredential = (lib.mapAttrsToList (name: k: "${credName name}:${k.file}") allKeys) ++ [
          "s3-access-key:${cfg.s3.accessKeyFile}"
          "s3-secret-key:${cfg.s3.secretKeyFile}"
          "login-kdf-key:${cfg.loginKdfKeyFile}"
        ];
        Restart = "on-failure";

        # Hardening: the service keeps no local state — it needs only the PG
        # socket and outbound network (to the object store).
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
      };
    };
  };
}
