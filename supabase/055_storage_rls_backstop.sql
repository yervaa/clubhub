-- ─── 055: Storage RLS backstop for announcement-attachments ──────────────────
-- Defense-in-depth. All real I/O happens through the service-role admin client,
-- which bypasses RLS, so these policies do NOT change current upload/download
-- behavior. They add a database-level floor so that if any code path ever uses
-- the anon/authenticated key directly against storage.objects, access is still
-- scoped to the club in the object path.
--
-- Object path convention (see migration 042 / clubs/actions.ts):
--   {clubId}/{announcementId}/{uuid}-{filename}
-- so storage.foldername(name) = {clubId, announcementId}:
--   (storage.foldername(name))[1] = club id
--   (storage.foldername(name))[2] = announcement id
--
-- IMPORTANT — cross-bucket safety: we deliberately NEVER cast path segments to
-- uuid (e.g. (storage.foldername(name))[1]::uuid). RLS predicates on
-- storage.objects are evaluated across rows of ALL buckets, and AND is not
-- guaranteed to short-circuit before the bucket_id filter, so casting an
-- attacker-influenceable path segment to uuid can throw on non-UUID-shaped
-- object names in other buckets. Instead we compare path segments AS TEXT
-- against the announcements table's uuid columns cast to text
-- (a.id::text / a.club_id::text), and pass the table's clean uuid columns to
-- the helper functions.
--
-- Helper signature reminder (club_id first, then auth.uid(), then key):
--   public.is_club_member(club_id, auth.uid())
--   public.is_club_officer(club_id, auth.uid())
--   public.has_club_permission(club_id, auth.uid(), 'permission.key')
--
-- Depends on: 042 (bucket + announcement_attachments), RBAC helper functions.
-- Idempotent.

begin;

-- ═══════════════════════════════════════════════════════════════════════════
-- 1. SELECT — member of the club in path segment 1 AND can view that
--    announcement (mirrors announcement_attachments_select_member in 042).
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "announcement_attachments_obj_select" on storage.objects;
create policy "announcement_attachments_obj_select"
  on storage.objects
  for select
  to authenticated
  using (
    bucket_id = 'announcement-attachments'
    and exists (
      select 1 from public.announcements a
      where a.id::text = (storage.foldername(name))[2]
        and a.club_id::text = (storage.foldername(name))[1]
        and public.is_club_member(a.club_id, auth.uid())
        and (
          (a.is_published = true and (a.scheduled_for is null or a.scheduled_for <= now()))
          or public.is_club_officer(a.club_id, auth.uid())
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.edit')
        )
    )
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- 2. INSERT — officer OR announcements.create in the club in path segment 1.
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "announcement_attachments_obj_insert" on storage.objects;
create policy "announcement_attachments_obj_insert"
  on storage.objects
  for insert
  to authenticated
  with check (
    bucket_id = 'announcement-attachments'
    and exists (
      select 1 from public.announcements a
      where a.id::text = (storage.foldername(name))[2]
        and a.club_id::text = (storage.foldername(name))[1]
        and (
          public.is_club_officer(a.club_id, auth.uid())
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.create')
        )
    )
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- 3. DELETE — officer OR announcements.delete in the club in path segment 1.
-- ═══════════════════════════════════════════════════════════════════════════

drop policy if exists "announcement_attachments_obj_delete" on storage.objects;
create policy "announcement_attachments_obj_delete"
  on storage.objects
  for delete
  to authenticated
  using (
    bucket_id = 'announcement-attachments'
    and exists (
      select 1 from public.announcements a
      where a.id::text = (storage.foldername(name))[2]
        and a.club_id::text = (storage.foldername(name))[1]
        and (
          public.is_club_officer(a.club_id, auth.uid())
          or public.has_club_permission(a.club_id, auth.uid(), 'announcements.delete')
        )
    )
  );

-- ═══════════════════════════════════════════════════════════════════════════
-- 4. Bucket-level backstops: cap size (5 MB) and restrict MIME types.
-- ═══════════════════════════════════════════════════════════════════════════

update storage.buckets
set
  file_size_limit = 5 * 1024 * 1024,
  allowed_mime_types = array[
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf'
  ]
where id = 'announcement-attachments';

commit;
