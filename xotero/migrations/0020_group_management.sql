alter type audit_action add value 'groups.list';
alter type audit_action add value 'groups.read';
alter type audit_action add value 'groups.create';
alter type audit_action add value 'groups.update';
alter type audit_action add value 'groups.delete';
alter table audit_events
    add column subject_group_id bigint check (subject_group_id > 0);

-- Explicit configured IDs never advance an identity sequence. Preserve its
-- high-water mark even when the highest generated group was already deleted.
select setval(
    pg_get_serial_sequence('groups', 'id'),
    greatest(coalesce(max(id), 1),
             coalesce(pg_sequence_last_value(pg_get_serial_sequence('groups', 'id')::regclass), 1)),
    true
) from groups;

-- Cleanup receipts must outlive their scope. Cascading them loses the only
-- durable identity of an interrupted/uncertain multipart upload. Updating them
-- during group deletion would invert registration's pending-token -> library
-- ordering. Preserve every old field and validate only new receipt admission.
alter table pending_uploads drop constraint pending_uploads_library_id_fkey;
alter table pending_uploads drop constraint pending_uploads_group_id_fkey;

create function xotero_pending_scope() returns trigger
language plpgsql volatile security invoker
as $$
declare scope_kind text;
begin
    select kind into scope_kind from library where id=new.library_id for share;
    if not found or (scope_kind='personal') <> (new.group_id is null) then
        raise exception 'invalid pending upload scope' using errcode='23503';
    end if;
    if new.group_id is not null then
        perform id from groups where id=new.group_id
            and library_id=new.library_id and library_kind=scope_kind for share;
        if not found then
            raise exception 'invalid pending upload scope' using errcode='23503';
        end if;
    end if;
    return new;
end
$$;
create trigger pending_uploads_scope before insert on pending_uploads
    for each row execute function xotero_pending_scope();
