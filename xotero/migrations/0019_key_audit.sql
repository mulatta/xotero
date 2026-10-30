alter type audit_action add value 'keys.list';
alter type audit_action add value 'keys.create';
alter type audit_action add value 'keys.revoke';

-- Retain historical key attribution without keeping bearer material or an FK
-- that would prevent future credential removal.
alter table audit_events
    add column subject_key_id bigint check (subject_key_id > 0);

-- Historical explicit grants retain their established semantics. API-issued
-- individual grants carry a live policy ceiling, including after role changes.
alter table api_key_group_permissions
    add column policy_limited boolean not null default false;
