{ pkgs }:

pkgs.linkFarm "xotero-v13-migrations" (
  map
    (path: {
      name = builtins.baseNameOf path;
      inherit path;
    })
    [
      ../../xotero/migrations/0001_init.sql
      ../../xotero/migrations/0002_files.sql
      ../../xotero/migrations/0003_fulltext.sql
      ../../xotero/migrations/0004_fulltext_search.sql
      ../../xotero/migrations/0005_item_search.sql
      ../../xotero/migrations/0006_item_columns.sql
      ../../xotero/migrations/0007_item_columns_fixes.sql
      ../../xotero/migrations/0008_identity.sql
      ../../xotero/migrations/0009_file_blob_key.sql
      ../../xotero/migrations/0010_login_sessions.sql
      ../../xotero/migrations/0011_private_groups.sql
      ../../xotero/migrations/0012_pending_uploads.sql
      ../../xotero/migrations/0013_compressed_files.sql
    ]
)
