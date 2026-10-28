-- Blob identity is global: historical files may share bytes across libraries.
-- Claims and deleted tombstones survive retries and block future publication.
create table blob_retirements (
    blob_key       text primary key check (btrim(blob_key) <> ''),
    not_before     timestamptz not null,
    state          text not null default 'queued'
                   check (state in ('queued', 'claimed', 'deleted')),
    retry_after    timestamptz not null default '-infinity',
    attempts       bigint not null default 0 check (attempts >= 0),
    deleted_at     timestamptz,
    check ((state = 'deleted') = (deleted_at is not null))
);

create index blob_retirements_due_idx on blob_retirements (not_before, retry_after)
    where state <> 'deleted';
create index file_blob_key_idx on file (blob_key);

-- Only promises issued with this policy can be reconstructed. No operational
-- pre-migration URL history exists; populated file rows remain untouched.
create table storage_policy (
    singleton                  boolean primary key default true check (singleton),
    max_issued_presign_ttl      bigint not null
                               check (max_issued_presign_ttl between 0 and 4294967295)
);
insert into storage_policy (max_issued_presign_ttl) values (0);
