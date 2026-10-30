-- Browser credentials are independent of desktop enrollment. Only digests cross
-- the database boundary; an identity unlink must remain possible with sessions.
alter type audit_action add value 'web.login';
alter type audit_action add value 'web.logout';

alter table api_keys add constraint api_keys_id_user_key unique (id, user_id);

create table web_challenges (
    token_hash bytea primary key check (octet_length(token_hash) = 32),
    browser_hash bytea not null check (octet_length(browser_hash) = 32),
    origin text not null,
    expires_at timestamptz not null default (clock_timestamp() + interval '10 minutes')
);
create index web_challenges_browser_idx on web_challenges(browser_hash);

create table web_sessions (
    token_hash bytea primary key check (octet_length(token_hash) = 32),
    browser_hash bytea not null check (octet_length(browser_hash) = 32),
    csrf_hash bytea not null check (octet_length(csrf_hash) = 32),
    origin text not null,
    user_id bigint not null references users(id),
    library_id bigint not null references library(id),
    issuer text not null,
    subject text not null,
    api_key_id bigint not null unique,
    created_at timestamptz not null default clock_timestamp(),
    expires_at timestamptz not null default (clock_timestamp() + interval '8 hours'),
    revoked_at timestamptz,
    foreign key (api_key_id, user_id) references api_keys(id, user_id) on delete cascade,
    check (expires_at > created_at)
);
create unique index web_sessions_live_browser_idx on web_sessions(browser_hash)
    where revoked_at is null;
