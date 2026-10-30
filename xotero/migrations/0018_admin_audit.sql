alter type audit_action add value 'admin.users';
alter type audit_action add value 'admin.create-user';
alter type audit_action add value 'admin.update-user';
alter type audit_action add value 'admin.set-role';
alter type audit_action add value 'admin.link-identity';

-- Prelock the invariant core's complete candidate set before authentication
-- locks keys/sessions. All supported role/mapping changes take this sentinel;
-- its rediscovery in xotero_change_authority therefore cannot add earlier rows.
-- This function is NOT authentication: callers must validate a live Web session.
create function xotero_lock_admin_users(actor_id bigint, target_id bigint)
returns void language plpgsql volatile security invoker
as $$
declare candidates bigint[];
begin
    perform xotero_lock_instance_authority();
    select array_agg(id order by id) into candidates from (
        select user_id as id from instance_admins
        union select actor_id union select target_id
    ) ids where id is not null;
    perform l.id from library l where l.id in (
        select p.library_id from personal_libraries p where p.user_id=any(candidates)
        union select g.library_id from groups g where g.owner_user_id=target_id
    ) order by l.id for share;
    perform g.id from groups g where g.owner_user_id=target_id order by g.id for share;
    perform u.id from users u where u.id=any(candidates) order by u.id for update;
    perform a.user_id from instance_admins a where a.user_id=any(candidates)
        order by a.user_id for update;
    perform p.user_id from personal_libraries p where p.user_id=any(candidates)
        order by p.user_id for share;
    perform e.user_id from external_identities e where e.user_id=any(candidates)
        order by e.issuer,e.subject for update;
end
$$;
