-- 0009 inferred this namespace without inspecting storage. Classification is
-- not proof of damage: the current object must win whenever its bytes verify.
create table legacy_blob_reconciliation (
    library_id bigint not null,
    item_key text not null,
    blob_key text not null,
    blob_md5 text not null,
    filesize bigint not null,
    compressed boolean not null,
    primary key (library_id, item_key)
);

insert into legacy_blob_reconciliation
    (library_id, item_key, blob_key, blob_md5, filesize, compressed)
select library_id, item_key, blob_key, blob_md5, filesize, compressed
from file
where library_id <> 1
  and blob_key = 'libraries/' || library_id::text || '/' || item_key
  and not starts_with(item_key, 'uploads/');
