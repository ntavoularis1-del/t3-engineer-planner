-- T3 Engineer Planner – Team Edition
-- Εκτέλεση μία φορά στο Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  email text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 100),
  owner_id uuid not null references auth.users(id) on delete restrict,
  invite_code text not null unique default upper(encode(gen_random_bytes(5), 'hex')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.memberships (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','editor','viewer')),
  joined_at timestamptz not null default now(),
  primary key (workspace_id,user_id)
);

create table if not exists public.entities (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  entity_type text not null check (entity_type in ('project','task','meeting','note','contact','dailyLog')),
  entity_id text not null,
  payload jsonb not null default '{}'::jsonb,
  created_by uuid references auth.users(id) on delete set null default auth.uid(),
  updated_by uuid references auth.users(id) on delete set null default auth.uid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (workspace_id,entity_type,entity_id)
);

create table if not exists public.activity_logs (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid references auth.users(id) on delete set null,
  action text not null check (action in ('insert','update','delete')),
  entity_type text not null,
  entity_id text not null,
  title text,
  created_at timestamptz not null default now()
);

create index if not exists entities_workspace_updated_idx on public.entities(workspace_id,updated_at desc);
create index if not exists activity_workspace_created_idx on public.activity_logs(workspace_id,created_at desc);
create index if not exists memberships_user_idx on public.memberships(user_id);

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path=public as $$
begin
  new.updated_at=now();
  return new;
end;
$$;

drop trigger if exists profiles_touch_updated_at on public.profiles;
create trigger profiles_touch_updated_at before update on public.profiles for each row execute function public.touch_updated_at();
drop trigger if exists workspaces_touch_updated_at on public.workspaces;
create trigger workspaces_touch_updated_at before update on public.workspaces for each row execute function public.touch_updated_at();
drop trigger if exists entities_touch_updated_at on public.entities;
create trigger entities_touch_updated_at before update on public.entities for each row execute function public.touch_updated_at();

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles(id,full_name,email)
  values(new.id,coalesce(new.raw_user_meta_data->>'full_name',split_part(new.email,'@',1)),new.email)
  on conflict(id) do update set email=excluded.email;
  return new;
end;
$$;

drop trigger if exists on_t3_auth_user_created on auth.users;
create trigger on_t3_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

insert into public.profiles(id,full_name,email)
select id,coalesce(raw_user_meta_data->>'full_name',split_part(email,'@',1)),email from auth.users
on conflict(id) do nothing;

create or replace function public.is_workspace_member(p_workspace_id uuid)
returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.memberships m where m.workspace_id=p_workspace_id and m.user_id=auth.uid());
$$;

create or replace function public.can_edit_workspace(p_workspace_id uuid)
returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.memberships m where m.workspace_id=p_workspace_id and m.user_id=auth.uid() and m.role in ('owner','editor'));
$$;

create or replace function public.is_workspace_owner(p_workspace_id uuid)
returns boolean language sql stable security definer set search_path=public as $$
  select exists(select 1 from public.memberships m where m.workspace_id=p_workspace_id and m.user_id=auth.uid() and m.role='owner');
$$;

alter table public.profiles enable row level security;
alter table public.workspaces enable row level security;
alter table public.memberships enable row level security;
alter table public.entities enable row level security;
alter table public.activity_logs enable row level security;

drop policy if exists profiles_select_self on public.profiles;
create policy profiles_select_self on public.profiles for select to authenticated using (id=auth.uid());
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated using (id=auth.uid()) with check (id=auth.uid());

drop policy if exists workspaces_select_member on public.workspaces;
create policy workspaces_select_member on public.workspaces for select to authenticated using (public.is_workspace_member(id));
drop policy if exists workspaces_update_owner on public.workspaces;
create policy workspaces_update_owner on public.workspaces for update to authenticated using (public.is_workspace_owner(id)) with check (public.is_workspace_owner(id));

drop policy if exists memberships_select_member on public.memberships;
create policy memberships_select_member on public.memberships for select to authenticated using (public.is_workspace_member(workspace_id));

drop policy if exists entities_select_member on public.entities;
create policy entities_select_member on public.entities for select to authenticated using (public.is_workspace_member(workspace_id));
drop policy if exists entities_insert_editor on public.entities;
create policy entities_insert_editor on public.entities for insert to authenticated with check (public.can_edit_workspace(workspace_id) and coalesce(updated_by,auth.uid())=auth.uid());
drop policy if exists entities_update_editor on public.entities;
create policy entities_update_editor on public.entities for update to authenticated using (public.can_edit_workspace(workspace_id)) with check (public.can_edit_workspace(workspace_id) and coalesce(updated_by,auth.uid())=auth.uid());
drop policy if exists entities_delete_editor on public.entities;
create policy entities_delete_editor on public.entities for delete to authenticated using (public.can_edit_workspace(workspace_id));

drop policy if exists activity_select_member on public.activity_logs;
create policy activity_select_member on public.activity_logs for select to authenticated using (public.is_workspace_member(workspace_id));

create or replace function public.create_workspace(p_name text)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_workspace uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if exists(select 1 from public.memberships where user_id=auth.uid()) then raise exception 'User already belongs to a workspace'; end if;
  insert into public.workspaces(name,owner_id) values(trim(p_name),auth.uid()) returning id into v_workspace;
  insert into public.memberships(workspace_id,user_id,role) values(v_workspace,auth.uid(),'owner');
  return v_workspace;
end;
$$;

create or replace function public.join_workspace_by_code(p_code text)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_workspace uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if exists(select 1 from public.memberships where user_id=auth.uid()) then raise exception 'User already belongs to a workspace'; end if;
  select id into v_workspace from public.workspaces where invite_code=upper(trim(p_code));
  if v_workspace is null then raise exception 'Invalid invite code'; end if;
  insert into public.memberships(workspace_id,user_id,role) values(v_workspace,auth.uid(),'editor');
  return v_workspace;
end;
$$;

create or replace function public.get_workspace_members(p_workspace_id uuid)
returns table(user_id uuid,full_name text,email text,role text,joined_at timestamptz)
language plpgsql stable security definer set search_path=public as $$
begin
  if not public.is_workspace_member(p_workspace_id) then raise exception 'Access denied'; end if;
  return query select m.user_id,p.full_name,p.email,m.role,m.joined_at
  from public.memberships m left join public.profiles p on p.id=m.user_id
  where m.workspace_id=p_workspace_id order by case m.role when 'owner' then 1 when 'editor' then 2 else 3 end,m.joined_at;
end;
$$;

create or replace function public.set_member_role(p_workspace_id uuid,p_user_id uuid,p_role text)
returns void language plpgsql security definer set search_path=public as $$
begin
  if not public.is_workspace_owner(p_workspace_id) then raise exception 'Owner access required'; end if;
  if p_role not in ('editor','viewer') then raise exception 'Invalid role'; end if;
  update public.memberships set role=p_role where workspace_id=p_workspace_id and user_id=p_user_id and role<>'owner';
end;
$$;

create or replace function public.regenerate_workspace_invite(p_workspace_id uuid)
returns text language plpgsql security definer set search_path=public as $$
declare v_code text;
begin
  if not public.is_workspace_owner(p_workspace_id) then raise exception 'Owner access required'; end if;
  v_code=upper(encode(gen_random_bytes(5),'hex'));
  update public.workspaces set invite_code=v_code where id=p_workspace_id;
  return v_code;
end;
$$;

create or replace function public.audit_entity_change()
returns trigger language plpgsql security definer set search_path=public as $$
declare v_row public.entities;
begin
  if tg_op='DELETE' then v_row:=old; else v_row:=new; end if;
  insert into public.activity_logs(workspace_id,user_id,action,entity_type,entity_id,title)
  values(v_row.workspace_id,auth.uid(),lower(tg_op),v_row.entity_type,v_row.entity_id,
    coalesce(v_row.payload->>'title',v_row.payload->>'summary',v_row.entity_id));
  if tg_op='DELETE' then return old; else return new; end if;
end;
$$;

drop trigger if exists entities_audit_change on public.entities;
create trigger entities_audit_change after insert or update or delete on public.entities for each row execute function public.audit_entity_change();

create or replace function public.get_recent_activity(p_workspace_id uuid,p_limit integer default 10)
returns table(action text,entity_type text,entity_id text,title text,actor_name text,created_at timestamptz)
language plpgsql stable security definer set search_path=public as $$
begin
  if not public.is_workspace_member(p_workspace_id) then raise exception 'Access denied'; end if;
  return query select a.action,a.entity_type,a.entity_id,a.title,coalesce(p.full_name,p.email,'Μέλος'),a.created_at
  from public.activity_logs a left join public.profiles p on p.id=a.user_id
  where a.workspace_id=p_workspace_id order by a.created_at desc limit greatest(1,least(coalesce(p_limit,10),50));
end;
$$;

grant usage on schema public to authenticated;
revoke all on public.profiles,public.workspaces,public.memberships,public.entities,public.activity_logs from anon;
grant select,update on public.profiles to authenticated;
grant select,update on public.workspaces to authenticated;
grant select on public.memberships to authenticated;
grant select,insert,update,delete on public.entities to authenticated;
grant select on public.activity_logs to authenticated;
revoke execute on function public.create_workspace(text) from public,anon;
revoke execute on function public.join_workspace_by_code(text) from public,anon;
revoke execute on function public.get_workspace_members(uuid) from public,anon;
revoke execute on function public.set_member_role(uuid,uuid,text) from public,anon;
revoke execute on function public.regenerate_workspace_invite(uuid) from public,anon;
revoke execute on function public.get_recent_activity(uuid,integer) from public,anon;
grant execute on function public.create_workspace(text) to authenticated;
grant execute on function public.join_workspace_by_code(text) to authenticated;
grant execute on function public.get_workspace_members(uuid) to authenticated;
grant execute on function public.set_member_role(uuid,uuid,text) to authenticated;
grant execute on function public.regenerate_workspace_invite(uuid) to authenticated;
grant execute on function public.get_recent_activity(uuid,integer) to authenticated;

alter table public.entities replica identity full;
do $$
begin
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='entities') then
    alter publication supabase_realtime add table public.entities;
  end if;
end;
$$;

-- Αναβάθμιση v2: αναθέσεις χρηστών και ειδοποιήσεις ομάδας.
-- Τα στοιχεία ανάθεσης/ολοκλήρωσης αποθηκεύονται με ασφάλεια στο payload
-- των εργασιών, οπότε δεν απαιτείται μεταβολή ή διαγραφή υπαρχόντων δεδομένων.

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
  if new.entity_type <> 'task' then return new; end if;
  select coalesce(full_name,email,'Μέλος') into v_actor_name
    from public.profiles where id=auth.uid();
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
    insert into public.notifications(workspace_id,task_id,event_type,title,message,actor_id,assignee_id)
    values(new.workspace_id,new.entity_id,'assigned','Νέα ανάθεση εργασίας',
      format('%s ανέθεσε την εργασία «%s» στον/στην %s.',v_actor_name,v_title,v_assignee_name),
      auth.uid(),v_new_assignee::uuid);
  end if;
  if v_new_status='done' and v_old_status is distinct from 'done' then
    insert into public.notifications(workspace_id,task_id,event_type,title,message,actor_id,assignee_id)
    values(new.workspace_id,new.entity_id,'completed','Η εργασία ολοκληρώθηκε',
      format('%s δήλωσε ότι ολοκλήρωσε την εργασία «%s». %s',v_actor_name,v_title,v_note),
      auth.uid(),nullif(v_new_assignee,'')::uuid);
  elsif v_new_status<>'done' and v_old_status='done' then
    insert into public.notifications(workspace_id,task_id,event_type,title,message,actor_id,assignee_id)
    values(new.workspace_id,new.entity_id,'reopened','Η εργασία άνοιξε ξανά',
      format('%s επέστρεψε την εργασία «%s» στις εκκρεμότητες.',v_actor_name,v_title),
      auth.uid(),nullif(v_new_assignee,'')::uuid);
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
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='notifications') then
    alter publication supabase_realtime add table public.notifications;
  end if;
end;
$$;
