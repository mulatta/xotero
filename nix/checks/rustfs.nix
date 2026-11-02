{ pkgs }:

# RustFS 1.0.4 and its main branch omit StorageClass from multipart listings,
# which rust-s3 0.38 requires. Keep the provider correction local rather than
# replacing the SDK parser or changing unrelated inputs.
pkgs.rustfs.overrideAttrs (old: {
  patches = (old.patches or [ ]) ++ [ ../patches/rustfs-list-multipart-storage-class.patch ];
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    cargo test --offline --release -p rustfs --lib \
      storage::s3_api::multipart::tests::test_list_multipart_uploads_reports_effective_storage_class \
      -- --exact --nocapture
    runHook postCheck
  '';
})
