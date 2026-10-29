create table instance_admins (
    user_id bigint primary key references users(id) on delete restrict,
    created_at timestamptz not null default now()
);

-- Completion is independent of mutable users, roles, and external mappings.
create table bootstrap_state (
    name text primary key check (name in ('identity', 'instance-admin')),
    completed_at timestamptz not null default now()
);
-- Upgrades must not reopen automatic identity provisioning or grant a role.
insert into bootstrap_state(name)
select 'identity' where exists(select 1 from personal_libraries);

create type audit_action as enum (
    'bootstrap.identity', 'bootstrap.instance-admin',
    'authority.revoke-admin', 'authority.disable-user', 'authority.unlink-identity'
);
create type audit_outcome as enum ('success', 'noop', 'denied');
create table audit_events (
    id bigint generated always as identity primary key,
    actor_user_id bigint check (actor_user_id > 0),
    subject_user_id bigint check (subject_user_id > 0),
    action audit_action not null,
    outcome audit_outcome not null,
    request_id uuid not null,
    occurred_at timestamptz not null default clock_timestamp()
);
-- Historical IDs intentionally survive account removal; no claims or free text.
create index audit_events_request_id_idx on audit_events(request_id);

create function xotero_append_audit(
    actor_id bigint, target_id bigint, event_action audit_action,
    event_outcome audit_outcome, correlation uuid
) returns void language sql volatile security invoker
as $$
    insert into audit_events(actor_user_id,subject_user_id,action,outcome,request_id)
    values(actor_id,target_id,event_action,event_outcome,correlation)
$$;

create function xotero_lock_instance_authority() returns void
language sql volatile security invoker
as $$ select pg_advisory_xact_lock(525207744336::bigint) $$;

-- Shared definition for bootstrap and every authority-reducing transition.
create function xotero_reachable_admins() returns table(user_id bigint)
language sql stable security invoker
as $$
    select a.user_id from instance_admins a
    join users u on u.id=a.user_id and u.disabled_at is null
    join personal_libraries p on p.user_id=u.id
    join library l on l.id=p.library_id and l.kind=p.library_kind
    where l.kind='personal'
      and exists(select 1 from external_identities e where e.user_id=u.id)
$$;

create type authority_change as enum ('revoke-admin', 'disable-user', 'unlink-identity');
create type authority_change_result as enum ('success', 'noop', 'conflict', 'missing');

-- Invariant core, NOT an authentication boundary: future callers must verify
-- live authenticated actor authority before calling, in the same transaction.
-- All grants/relinks/ownership changes must take this sentinel before row locks.
-- A returned denial/noop must be COMMITted by the caller to retain its audit.
create function xotero_change_authority(
    target_id bigint, change authority_change, identity_issuer text,
    identity_subject text, actor_id bigint, correlation uuid
) returns authority_change_result
language plpgsql volatile security invoker
as $$
declare
    candidates bigint[];
    result authority_change_result;
    event_action audit_action;
    target_reachable boolean;
begin
    perform xotero_lock_instance_authority();
    select array_agg(id order by id) into candidates from (
        select user_id as id from instance_admins union select target_id
    ) ids;
    -- Discovery is not authorization. Positive evidence is locked in shared
    -- application order: library -> user/role -> ownership -> exact identities.
    -- Libraries are not mutated, so SHARE also permits enrollment SHARE locks.
    perform l.id from library l
        where l.id in (select p.library_id from personal_libraries p
                       where p.user_id=any(candidates))
        order by l.id for share;
    perform u.id from users u where u.id=any(candidates) order by u.id for update;
    perform a.user_id from instance_admins a where a.user_id=any(candidates)
        order by a.user_id for update;
    perform p.user_id from personal_libraries p where p.user_id=any(candidates)
        order by p.user_id for share;
    perform e.user_id from external_identities e where e.user_id=any(candidates)
        order by e.issuer,e.subject for update;
    select exists(select 1 from xotero_reachable_admins() a where a.user_id=target_id)
        into target_reachable;
    event_action := case change
        when 'revoke-admin' then 'authority.revoke-admin'::audit_action
        when 'disable-user' then 'authority.disable-user'::audit_action
        when 'unlink-identity' then 'authority.unlink-identity'::audit_action end;
    if not exists(select 1 from users where id=target_id) then
        result := 'missing';
    elsif (change='revoke-admin' and not exists(
               select 1 from instance_admins where user_id=target_id))
       or (change='disable-user' and exists(
               select 1 from users where id=target_id and disabled_at is not null))
       or (change='unlink-identity' and not exists(
               select 1 from external_identities where user_id=target_id
               and issuer=identity_issuer and subject=identity_subject)) then
        result := 'noop';
    elsif (change='unlink-identity' and exists(
           select 1 from users where id=target_id and disabled_at is null) and
           (select count(*) from external_identities where user_id=target_id)<=1)
       or (target_reachable and (select count(*) from xotero_reachable_admins())<=1
           and (change<>'unlink-identity' or
                (select count(*) from external_identities where user_id=target_id)<=1)) then
        result := 'conflict';
    else
        case change
        when 'revoke-admin' then delete from instance_admins where user_id=target_id;
        when 'disable-user' then update users set disabled_at=now() where id=target_id;
        when 'unlink-identity' then delete from external_identities where user_id=target_id
            and issuer=identity_issuer and subject=identity_subject;
        end case;
        result := 'success';
    end if;
    perform xotero_append_audit(actor_id,target_id,event_action,
        case result when 'success' then 'success'::audit_outcome
                    when 'noop' then 'noop'::audit_outcome
                    else 'denied'::audit_outcome end,correlation);
    return result;
end
$$;
