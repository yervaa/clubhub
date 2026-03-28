-- ClubHub RBAC Backfill + Auto-Sync Triggers
--
-- STEP 1: Seeds system roles (President / Officer / Member) for every existing
--         club that was created before 013_rbac_foundation.sql was applied.
--         Idempotent: skips clubs that already have system roles.
--
-- STEP 2: Adds triggers on club_members so that future INSERTs and role-UPDATE
--         operations automatically keep member_roles in sync with the legacy
--         role column — no application-layer changes needed for join/role-update
--         flows.
--
-- Apply after 013_rbac_foundation.sql.

-- ─── STEP 1: BACKFILL ─────────────────────────────────────────────────────────

do $$
declare
  v_club              record;
  v_president_role_id uuid;
  v_officer_role_id   uuid;
  v_member_role_id    uuid;
  v_president_user_id uuid;
begin
  for v_club in
    select id, created_by from public.clubs
  loop

    -- Skip clubs that already have system roles (idempotency guard).
    if exists (
      select 1 from public.club_roles
      where club_id = v_club.id and is_system = true
    ) then
      continue;
    end if;

    -- Create the three system roles.
    insert into public.club_roles (club_id, name, description, is_system)
    values (v_club.id, 'President', 'Full control over the club', true)
    returning id into v_president_role_id;

    insert into public.club_roles (club_id, name, description, is_system)
    values (v_club.id, 'Officer', 'Manages events, announcements, and members', true)
    returning id into v_officer_role_id;

    insert into public.club_roles (club_id, name, description, is_system)
    values (v_club.id, 'Member', 'Standard club member', true)
    returning id into v_member_role_id;

    -- President gets every permission.
    insert into public.role_permissions (role_id, permission_id)
    select v_president_role_id, p.id from public.permissions p;

    -- Officer permissions.
    insert into public.role_permissions (role_id, permission_id)
    select v_officer_role_id, p.id
    from public.permissions p
    where p.key in (
      'members.view', 'members.invite',
      'events.create', 'events.edit',
      'announcements.create', 'announcements.edit',
      'reflections.create', 'reflections.edit',
      'insights.view'
    );

    -- Member permissions.
    insert into public.role_permissions (role_id, permission_id)
    select v_member_role_id, p.id
    from public.permissions p
    where p.key in ('members.view', 'insights.view');

    -- Determine who becomes President:
    --   1. Prefer the club creator if they are still a member.
    --   2. Otherwise fall back to the earliest-joined officer.
    --   3. If neither applies (all members removed), skip — leave no President
    --      rather than guess. This is an edge case for very early test clubs.
    v_president_user_id := null;

    if exists (
      select 1 from public.club_members
      where club_id = v_club.id and user_id = v_club.created_by
    ) then
      v_president_user_id := v_club.created_by;
    else
      select cm.user_id into v_president_user_id
      from public.club_members cm
      where cm.club_id = v_club.id and cm.role = 'officer'
      order by cm.joined_at
      limit 1;
      -- Documented fallback: a non-creator officer becomes President.
      -- This preserves the at-least-one-President invariant for clubs where
      -- the original creator has left.
    end if;

    if v_president_user_id is not null then
      insert into public.member_roles (user_id, club_id, role_id)
      values (v_president_user_id, v_club.id, v_president_role_id)
      on conflict do nothing;
    end if;

    -- All officers get the Officer RBAC role (including the creator — they hold
    -- both President and Officer system roles so either permission check works).
    insert into public.member_roles (user_id, club_id, role_id)
    select cm.user_id, v_club.id, v_officer_role_id
    from public.club_members cm
    where cm.club_id = v_club.id and cm.role = 'officer'
    on conflict do nothing;

    -- All regular members get the Member RBAC role.
    insert into public.member_roles (user_id, club_id, role_id)
    select cm.user_id, v_club.id, v_member_role_id
    from public.club_members cm
    where cm.club_id = v_club.id and cm.role = 'member'
    on conflict do nothing;

  end loop;
end;
$$;

-- ─── STEP 2A: AUTO-ASSIGN RBAC ROLE ON JOIN ──────────────────────────────────
-- When a new row is inserted into club_members, automatically assign the
-- matching system RBAC role (Officer or Member). Runs as security definer so
-- it can write to member_roles without the joining user holding assign_roles.
-- If no system roles exist yet (e.g. during create_club_with_creator_membership
-- before seed_default_club_roles runs), the trigger is a no-op.

create or replace function public.assign_rbac_role_on_member_insert()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_role_name    text;
  v_rbac_role_id uuid;
begin
  v_role_name := case when new.role = 'officer' then 'Officer' else 'Member' end;

  select id into v_rbac_role_id
  from public.club_roles
  where club_id = new.club_id
    and name    = v_role_name
    and is_system = true;

  -- No RBAC roles exist yet (during club creation); seed_default_club_roles
  -- will handle assignment. Skip silently.
  if v_rbac_role_id is null then
    return new;
  end if;

  insert into public.member_roles (user_id, club_id, role_id)
  values (new.user_id, new.club_id, v_rbac_role_id)
  on conflict do nothing;

  return new;
end;
$$;

drop trigger if exists assign_rbac_role_on_member_insert on public.club_members;
create trigger assign_rbac_role_on_member_insert
after insert on public.club_members
for each row execute function public.assign_rbac_role_on_member_insert();

-- ─── STEP 2B: SYNC RBAC ROLE ON LEGACY ROLE UPDATE ───────────────────────────
-- When update_club_member_role changes officer ↔ member, swap the corresponding
-- system RBAC roles. Leaves any additional custom or President roles untouched.

create or replace function public.sync_rbac_role_on_member_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_old_name     text;
  v_new_name     text;
  v_old_role_id  uuid;
  v_new_role_id  uuid;
begin
  if old.role = new.role then
    return new;
  end if;

  v_old_name := case when old.role = 'officer' then 'Officer' else 'Member' end;
  v_new_name := case when new.role = 'officer' then 'Officer' else 'Member' end;

  select id into v_old_role_id
  from public.club_roles
  where club_id = new.club_id and name = v_old_name and is_system = true;

  select id into v_new_role_id
  from public.club_roles
  where club_id = new.club_id and name = v_new_name and is_system = true;

  -- Remove old system RBAC role.
  if v_old_role_id is not null then
    delete from public.member_roles
    where user_id = new.user_id
      and club_id = new.club_id
      and role_id = v_old_role_id;
  end if;

  -- Assign new system RBAC role.
  if v_new_role_id is not null then
    insert into public.member_roles (user_id, club_id, role_id)
    values (new.user_id, new.club_id, v_new_role_id)
    on conflict do nothing;
  end if;

  return new;
end;
$$;

drop trigger if exists sync_rbac_role_on_member_update on public.club_members;
create trigger sync_rbac_role_on_member_update
after update of role on public.club_members
for each row execute function public.sync_rbac_role_on_member_update();

-- ─── STEP 2C: CLEAN UP RBAC ROLES ON MEMBER REMOVAL ─────────────────────────
-- When a row is deleted from club_members, remove all member_roles for that
-- user in that club. Cascade on the FK would also work, but an explicit trigger
-- is clearer and more maintainable.

create or replace function public.remove_rbac_roles_on_member_delete()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.member_roles
  where user_id = old.user_id
    and club_id = old.club_id;

  return old;
end;
$$;

drop trigger if exists remove_rbac_roles_on_member_delete on public.club_members;
create trigger remove_rbac_roles_on_member_delete
after delete on public.club_members
for each row execute function public.remove_rbac_roles_on_member_delete();
