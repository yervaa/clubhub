-- Allow 1-character club names and announcement/event titles.
-- Apply this on existing projects after prior migrations.

do $$
declare
  constraint_name text;
begin
  select con.conname
  into constraint_name
  from pg_constraint con
  join pg_class rel on rel.oid = con.conrelid
  join pg_namespace nsp on nsp.oid = rel.relnamespace
  where nsp.nspname = 'public'
    and rel.relname = 'clubs'
    and con.contype = 'c'
    and pg_get_constraintdef(con.oid) like '%char_length(name) >= 2%';

  if constraint_name is not null then
    execute format('alter table public.clubs drop constraint %I', constraint_name);
  end if;
end $$;

alter table public.clubs
add constraint clubs_name_length_check
check (char_length(name) >= 1);

do $$
declare
  constraint_name text;
begin
  select con.conname
  into constraint_name
  from pg_constraint con
  join pg_class rel on rel.oid = con.conrelid
  join pg_namespace nsp on nsp.oid = rel.relnamespace
  where nsp.nspname = 'public'
    and rel.relname = 'announcements'
    and con.contype = 'c'
    and pg_get_constraintdef(con.oid) like '%char_length(title) >= 2%';

  if constraint_name is not null then
    execute format('alter table public.announcements drop constraint %I', constraint_name);
  end if;
end $$;

alter table public.announcements
add constraint announcements_title_length_check
check (char_length(title) >= 1);

do $$
declare
  constraint_name text;
begin
  select con.conname
  into constraint_name
  from pg_constraint con
  join pg_class rel on rel.oid = con.conrelid
  join pg_namespace nsp on nsp.oid = rel.relnamespace
  where nsp.nspname = 'public'
    and rel.relname = 'events'
    and con.contype = 'c'
    and pg_get_constraintdef(con.oid) like '%char_length(title) >= 2%';

  if constraint_name is not null then
    execute format('alter table public.events drop constraint %I', constraint_name);
  end if;
end $$;

alter table public.events
add constraint events_title_length_check
check (char_length(title) >= 1);
