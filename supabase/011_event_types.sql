alter table public.events
add column if not exists event_type text;

update public.events
set event_type = 'Other'
where event_type is null;

alter table public.events
alter column event_type set default 'Other';

alter table public.events
alter column event_type set not null;

alter table public.events
drop constraint if exists events_event_type_check;

alter table public.events
add constraint events_event_type_check
check (event_type in ('Meeting', 'Workshop', 'Social', 'Competition', 'Fundraiser', 'Service', 'Other'));
