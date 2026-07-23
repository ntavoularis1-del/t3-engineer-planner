-- T3 Engineer Planner – Ασφαλής αναβάθμιση v2
-- Προσθέτει αναθέσεις/ειδοποιήσεις ΧΩΡΙΣ διαγραφή ή αλλαγή των υπαρχόντων δεδομένων.
-- Εκτέλεσε ολόκληρο το αρχείο μία φορά στο Supabase SQL Editor.

create table if not exists public.notifications (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  task_id text not null,
  event_type text not null check (event_type in ('assigned','completed','reopened')),
  title text not null,
  message text not null,
  actor_id uuid references auth.users(id) on delete set null,
  assignee_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists notifications_workspace_created_idx
  on public.notifications(workspace_id,created_at desc);

alter table public.notifications enable row level security;

drop policy if exists notifications_select_member on public.notifications;
create policy notifications_select_member
  on public.notifications
  for select
  to authenticated
  using (public.is_workspace_member(workspace_id));

revoke all on public.notifications from anon;
grant select on public.notifications to authenticated;

create or replace function public.notify_task_change()
returns trigger
language plpgsql
security definer
set search_path=public
as $$
declare
  v_actor_name text;
  v_title text;
  v_old_assignee text;
  v_new_assignee text;
  v_old_status text;
  v_new_status text;
  v_assignee_name text;
  v_note text;
begin
  if new.entity_type <> 'task' then
    return new;
  end if;

  select coalesce(full_name,email,'Μέλος')
  into v_actor_name
  from public.profiles
  where id=auth.uid();

  v_actor_name:=coalesce(v_actor_name,'Μέλος');
  v_title:=coalesce(new.payload->>'title','Εργασία');
  v_new_assignee:=coalesce(new.payload->>'assigneeId','');
  v_new_status:=coalesce(new.payload->>'status','pending');
  v_assignee_name:=coalesce(new.payload->>'assigneeName',new.payload->>'assignee','Μέλος');
  v_note:=coalesce(nullif(new.payload->>'completionNote',''),'Ολοκλήρωσα την εργασία.');

  if tg_op='UPDATE' then
    v_old_assignee:=coalesce(old.payload->>'assigneeId','');
    v_old_status:=coalesce(old.payload->>'status','pending');
  else
    v_old_assignee:='';
    v_old_status:='';
  end if;

  if v_new_assignee<>'' and v_new_assignee is distinct from v_old_assignee then
    insert into public.notifications(
      workspace_id,task_id,event_type,title,message,actor_id,assignee_id
    ) values (
      new.workspace_id,
      new.entity_id,
      'assigned',
      'Νέα ανάθεση εργασίας',
      format('%s ανέθεσε την εργασία «%s» στον/στην %s.',v_actor_name,v_title,v_assignee_name),
      auth.uid(),
      v_new_assignee::uuid
    );
  end if;

  if v_new_status='done' and v_old_status is distinct from 'done' then
    insert into public.notifications(
      workspace_id,task_id,event_type,title,message,actor_id,assignee_id
    ) values (
      new.workspace_id,
      new.entity_id,
      'completed',
      'Η εργασία ολοκληρώθηκε',
      format('%s δήλωσε ότι ολοκλήρωσε την εργασία «%s». %s',v_actor_name,v_title,v_note),
      auth.uid(),
      nullif(v_new_assignee,'')::uuid
    );
  elsif v_new_status<>'done' and v_old_status='done' then
    insert into public.notifications(
      workspace_id,task_id,event_type,title,message,actor_id,assignee_id
    ) values (
      new.workspace_id,
      new.entity_id,
      'reopened',
      'Η εργασία άνοιξε ξανά',
      format('%s επέστρεψε την εργασία «%s» στις εκκρεμότητες.',v_actor_name,v_title),
      auth.uid(),
      nullif(v_new_assignee,'')::uuid
    );
  end if;

  return new;
end;
$$;

drop trigger if exists entities_notify_task_change on public.entities;
create trigger entities_notify_task_change
after insert or update on public.entities
for each row execute function public.notify_task_change();

alter table public.notifications replica identity full;

do $$
begin
  if not exists(
    select 1
    from pg_publication_tables
    where pubname='supabase_realtime'
      and schemaname='public'
      and tablename='notifications'
  ) then
    alter publication supabase_realtime add table public.notifications;
  end if;
end;
$$;

