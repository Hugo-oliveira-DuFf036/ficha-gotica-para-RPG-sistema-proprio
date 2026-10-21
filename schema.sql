-- =====================================================================
-- SALA DA MASMORRA — schema Supabase (Postgres + RLS + RPC)
-- Rode este arquivo inteiro no SQL Editor do seu projeto Supabase.
-- É idempotente: pode ser executado de novo para atualizar as funções.
--
-- Modelo de segurança:
--   * Ninguém escreve direto nas tabelas. INSERT/UPDATE/DELETE estão
--     revogados; toda escrita passa por funções (RPC) SECURITY DEFINER
--     que validam quem é o usuário (auth.uid()), o papel (mestre/jogador),
--     as permissões, o tamanho e o formato dos dados.
--   * SELECT é liberado apenas por políticas RLS: só participantes ativos
--     enxergam os dados da própria sala.
--   * A chave "anon/publishable" no HTML é pública por desenho. A chave
--     service_role NUNCA vai para o HTML.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- Tabelas
-- ---------------------------------------------------------------------
create table if not exists public.rooms (
  id          uuid primary key default gen_random_uuid(),
  code        text not null unique check (code ~ '^[A-HJ-NP-Z2-9]{8,16}$'),
  name        text not null check (char_length(name) between 1 and 60),
  master_id   uuid not null references auth.users(id) on delete cascade,
  status      text not null default 'open' check (status in ('open','closed')),
  settings    jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  closed_at   timestamptz
);
create index if not exists rooms_master_idx on public.rooms(master_id, status);

create table if not exists public.room_members (
  room_id      uuid not null references public.rooms(id) on delete cascade,
  user_id      uuid not null references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 40),
  role         text not null check (role in ('master','player')),
  status       text not null default 'active' check (status in ('active','left','kicked')),
  perms        jsonb not null default '{}'::jsonb,
  joined_at    timestamptz not null default now(),
  left_at      timestamptz,
  primary key (room_id, user_id)
);
create index if not exists room_members_user_idx on public.room_members(user_id, status);

create table if not exists public.sheets (
  room_id     uuid not null,
  owner_id    uuid not null,
  data        jsonb not null,
  summary     jsonb not null default '{}'::jsonb,
  rev         integer not null default 1,
  updated_by  uuid,
  updated_at  timestamptz not null default now(),
  primary key (room_id, owner_id),
  foreign key (room_id, owner_id) references public.room_members(room_id, user_id) on delete cascade
);

create table if not exists public.room_events (
  id          bigint generated always as identity primary key,
  room_id     uuid not null references public.rooms(id) on delete cascade,
  user_id     uuid not null,
  author      text not null,
  kind        text not null check (kind in ('roll','hp','cond')),
  payload     jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);
create index if not exists room_events_room_idx on public.room_events(room_id, id);
create index if not exists room_events_rate_idx on public.room_events(room_id, user_id, created_at);

create table if not exists public.room_chat (
  id          bigint generated always as identity primary key,
  room_id     uuid not null references public.rooms(id) on delete cascade,
  user_id     uuid,
  author      text not null,
  kind        text not null default 'msg' check (kind in ('msg','system')),
  body        text not null check (char_length(body) between 1 and 1000),
  created_at  timestamptz not null default now()
);
create index if not exists room_chat_room_idx on public.room_chat(room_id, id);
create index if not exists room_chat_rate_idx on public.room_chat(room_id, user_id, created_at);

create table if not exists public.join_attempts (
  id       bigint generated always as identity primary key,
  user_id  uuid not null,
  at       timestamptz not null default now()
);
create index if not exists join_attempts_idx on public.join_attempts(user_id, at);

-- ---------------------------------------------------------------------
-- Funções internas (não chamáveis pelo cliente)
-- ---------------------------------------------------------------------
create or replace function public._require_user() returns uuid
language plpgsql stable set search_path = public as $$
declare u uuid := auth.uid();
begin
  if u is null then raise exception 'not_authenticated'; end if;
  return u;
end $$;

create or replace function public._err(p_code text, p_extra jsonb default '{}'::jsonb) returns jsonb
language sql immutable as $$ select jsonb_build_object('ok', false, 'error', p_code) || coalesce(p_extra,'{}'::jsonb) $$;

create or replace function public._clean_text(t text, maxlen int) returns text
language sql immutable as $$
  select left(btrim(regexp_replace(regexp_replace(coalesce(t,''), '[[:cntrl:]]+', ' ', 'g'), '\s+', ' ', 'g')), maxlen)
$$;

create or replace function public._gen_code(len int) returns text
language plpgsql volatile set search_path = public, extensions as $$
declare
  alpha constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; -- 32 símbolos, sem I O 0 1
  b bytea := gen_random_bytes(len);
  out text := '';
  i int;
begin
  for i in 0..len-1 loop
    out := out || substr(alpha, (get_byte(b, i) & 31) + 1, 1);
  end loop;
  return out;
end $$;

create or replace function public._perm_keys() returns text[]
language sql immutable as $$
  select array['vida_mana','atributos','pericias','condicoes','habilidades','inventario','equipamentos','identidade','rolar','chat']
$$;

create or replace function public._default_perms() returns jsonb
language sql immutable as $$
  select jsonb_build_object('vida_mana',true,'atributos',true,'pericias',true,'condicoes',true,'habilidades',true,
                            'inventario',true,'equipamentos',true,'identidade',true,'rolar',true,'chat',true)
$$;

create or replace function public._valid_perms(p jsonb) returns boolean
language sql immutable as $$
  select p is not null and jsonb_typeof(p) = 'object'
     and not exists (
       select 1 from jsonb_each(p) e
       where e.key <> all (public._perm_keys()) or jsonb_typeof(e.value) <> 'boolean'
     )
$$;

-- Chaves aceitas na ficha sincronizada, categoria de permissão e tipos aceitos.
-- Aparência, PDF, aba atual e histórico de rolagens ficam só no aparelho.
create or replace function public._sheet_spec() returns table(k text, cat text, ty text)
language sql immutable as $$
  values
   ('nome','identidade','string|number'),('raca','identidade','string|number'),('idade','identidade','string|number'),
   ('deus','identidade','string|number'),('classe','identidade','string|number'),('altura','identidade','string|number'),
   ('desl','identidade','string|number'),('lore','identidade','string'),('notas','identidade','string'),
   ('rcn','identidade','string'),('capa','identidade','string'),('xp','identidade','string|number'),
   ('fome','identidade','string|number'),('sede','identidade','string|number'),('sorte','identidade','string|number'),
   ('tn','identidade','string'),
   ('pts','atributos','object'),('attPool','atributos','string|number'),('attCap','atributos','string|number'),
   ('attNeg','atributos','boolean'),('rmode','atributos','string|number'),('plus','atributos','string'),
   ('plus2','atributos','string'),('rc','atributos','string'),('vb','atributos','string|number'),
   ('mb','atributos','string|number'),('tt','atributos','string'),('ts','atributos','string'),('ts2','atributos','string'),
   ('va','vida_mana','string|number'),('vm','vida_mana','string|number'),
   ('ma','vida_mana','string|number'),('mm','vida_mana','string|number'),
   ('sk','pericias','object'),('skBase','pericias','string|number'),('skMult','pericias','string|number'),
   ('skVal','pericias','string|number'),('cs','pericias','array'),
   ('cond','condicoes','array'),('condAuto','condicoes','boolean'),
   ('skl','habilidades','array'),
   ('inv','inventario','array'),('cats','inventario','array'),('moedas','inventario','object'),('recs','inventario','array'),
   ('armas','equipamentos','array'),('caex','equipamentos','string|number')
$$;

create or replace function public._default_settings() returns jsonb
language sql immutable as $$
  select jsonb_build_object('share_status', false, 'max_players', 8, 'default_perms', public._default_perms())
$$;

-- ---------------------------------------------------------------------
-- Helpers usados pelas políticas RLS
-- ---------------------------------------------------------------------
create or replace function public.is_member(p_room uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.room_members m
                 where m.room_id = p_room and m.user_id = auth.uid() and m.status = 'active')
$$;

create or replace function public.is_room_master(p_room uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.rooms r where r.id = p_room and r.master_id = auth.uid())
$$;

create or replace function public.room_shares_status(p_room uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select (r.settings->>'share_status')::boolean from public.rooms r where r.id = p_room), false)
$$;

-- ---------------------------------------------------------------------
-- RLS: somente leitura para participantes
-- ---------------------------------------------------------------------
alter table public.rooms         enable row level security;
alter table public.room_members  enable row level security;
alter table public.sheets        enable row level security;
alter table public.room_events   enable row level security;
alter table public.room_chat     enable row level security;
alter table public.join_attempts enable row level security;

drop policy if exists rooms_select on public.rooms;
create policy rooms_select on public.rooms for select to authenticated
  using (master_id = auth.uid() or public.is_member(id));

drop policy if exists members_select on public.room_members;
create policy members_select on public.room_members for select to authenticated
  using (user_id = auth.uid() or public.is_member(room_id) or public.is_room_master(room_id));

drop policy if exists sheets_select on public.sheets;
create policy sheets_select on public.sheets for select to authenticated
  using (public.is_room_master(room_id) or (owner_id = auth.uid() and public.is_member(room_id)));

drop policy if exists events_select on public.room_events;
create policy events_select on public.room_events for select to authenticated
  using (
    public.is_room_master(room_id)
    or (public.is_member(room_id) and (kind = 'roll' or user_id = auth.uid() or public.room_shares_status(room_id)))
  );

drop policy if exists chat_select on public.room_chat;
create policy chat_select on public.room_chat for select to authenticated
  using (public.is_room_master(room_id) or public.is_member(room_id));

-- ---------------------------------------------------------------------
-- RPC: salas
-- ---------------------------------------------------------------------
create or replace function public.create_room(p_name text, p_master_name text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  u uuid := public._require_user();
  n text := public._clean_text(p_name, 60);
  mn text := public._clean_text(p_master_name, 40);
  c text; rid uuid; tries int := 0;
begin
  if n = '' then return public._err('bad_name'); end if;
  if mn = '' then mn := 'Mestre'; end if;
  if (select count(*) from public.rooms where master_id = u and status = 'open') >= 5 then
    return public._err('too_many_rooms');
  end if;
  loop
    c := public._gen_code(10);
    begin
      insert into public.rooms(code, name, master_id, settings)
      values (c, n, u, public._default_settings()) returning id into rid;
      exit;
    exception when unique_violation then
      tries := tries + 1;
      if tries > 8 then return public._err('code_generation_failed'); end if;
    end;
  end loop;
  insert into public.room_members(room_id, user_id, display_name, role, perms)
  values (rid, u, mn, 'master', public._default_perms());
  insert into public.room_chat(room_id, user_id, author, kind, body)
  values (rid, null, 'Sala', 'system', 'Sala "' || n || '" criada por ' || mn || '.');
  return jsonb_build_object('ok', true, 'room_id', rid, 'code', c);
end $$;

create or replace function public.join_room(p_code text, p_name text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  u uuid := public._require_user();
  v_code text := upper(regexp_replace(coalesce(p_code,''), '[^A-Za-z0-9]', '', 'g'));
  nm text := public._clean_text(p_name, 40);
  r public.rooms%rowtype; m public.room_members%rowtype; maxp int; cnt int; announce boolean := false; existed boolean;
begin
  if nm = '' then return public._err('bad_name'); end if;
  if (select count(*) from public.join_attempts where user_id = u and at > now() - interval '10 minutes') >= 8 then
    return public._err('too_many_attempts');
  end if;
  select * into r from public.rooms where rooms.code = v_code;
  if not found then
    insert into public.join_attempts(user_id) values (u);
    return public._err('invalid_code');
  end if;
  if r.status <> 'open' then return public._err('room_closed'); end if;
  if r.master_id = u then
    return jsonb_build_object('ok', true, 'room_id', r.id, 'role', 'master', 'name', r.name);
  end if;
  select * into m from public.room_members where room_id = r.id and user_id = u for update;
  existed := found;  -- FOUND é sobrescrito pelos SELECTs seguintes
  if existed and m.status = 'kicked' then return public._err('kicked'); end if;
  maxp := coalesce((r.settings->>'max_players')::int, 8);
  if not existed or m.status = 'left' then
    select count(*) into cnt from public.room_members where room_id = r.id and role = 'player' and status = 'active';
    if cnt >= maxp then return public._err('room_full'); end if;
    announce := true;
  end if;
  if not existed then
    insert into public.room_members(room_id, user_id, display_name, role, perms)
    values (r.id, u, nm, 'player', coalesce(r.settings->'default_perms', public._default_perms()));
  else
    update public.room_members set status = 'active', display_name = nm, left_at = null
    where room_id = r.id and user_id = u;
  end if;
  if announce then
    insert into public.room_chat(room_id, user_id, author, kind, body)
    values (r.id, null, 'Sala', 'system', nm || ' entrou na sala.');
  end if;
  return jsonb_build_object('ok', true, 'room_id', r.id, 'role', 'player', 'name', r.name);
end $$;

create or replace function public.leave_room(p_room uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user(); m public.room_members%rowtype;
begin
  select * into m from public.room_members where room_id = p_room and user_id = u for update;
  if not found or m.status <> 'active' then return public._err('not_member'); end if;
  if m.role = 'master' then return public._err('master_cannot_leave'); end if;
  update public.room_members set status = 'left', left_at = now() where room_id = p_room and user_id = u;
  insert into public.room_chat(room_id, user_id, author, kind, body)
  values (p_room, null, 'Sala', 'system', m.display_name || ' saiu da sala.');
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.kick_member(p_room uuid, p_user uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user(); m public.room_members%rowtype;
begin
  if not exists (select 1 from public.rooms where id = p_room and master_id = u and status = 'open') then
    return public._err('forbidden');
  end if;
  select * into m from public.room_members where room_id = p_room and user_id = p_user for update;
  if not found or m.role = 'master' then return public._err('not_found'); end if;
  update public.room_members set status = 'kicked', left_at = now() where room_id = p_room and user_id = p_user;
  insert into public.room_chat(room_id, user_id, author, kind, body)
  values (p_room, null, 'Sala', 'system', m.display_name || ' foi removido(a) da sala pelo Mestre.');
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.set_member_perms(p_room uuid, p_user uuid, p_perms jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user(); np jsonb;
begin
  if not exists (select 1 from public.rooms where id = p_room and master_id = u and status = 'open') then
    return public._err('forbidden');
  end if;
  if not public._valid_perms(p_perms) then return public._err('bad_perms'); end if;
  update public.room_members
     set perms = public._default_perms() || perms || p_perms
   where room_id = p_room and user_id = p_user and role = 'player'
   returning perms into np;
  if np is null then return public._err('not_found'); end if;
  return jsonb_build_object('ok', true, 'perms', np);
end $$;

create or replace function public.set_room_settings(p_room uuid, p_settings jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user(); cur jsonb; nw jsonb; mp int;
begin
  if not exists (select 1 from public.rooms where id = p_room and master_id = u and status = 'open') then
    return public._err('forbidden');
  end if;
  if p_settings is null or jsonb_typeof(p_settings) <> 'object' then return public._err('bad_settings'); end if;
  if exists (select 1 from jsonb_object_keys(p_settings) k where k not in ('share_status','max_players','default_perms')) then
    return public._err('bad_settings');
  end if;
  select settings into cur from public.rooms where id = p_room;
  nw := cur;
  if p_settings ? 'share_status' then
    if jsonb_typeof(p_settings->'share_status') <> 'boolean' then return public._err('bad_settings'); end if;
    nw := nw || jsonb_build_object('share_status', p_settings->'share_status');
  end if;
  if p_settings ? 'max_players' then
    if jsonb_typeof(p_settings->'max_players') <> 'number' then return public._err('bad_settings'); end if;
    mp := (p_settings->>'max_players')::int;
    if mp < 1 or mp > 20 then return public._err('bad_settings'); end if;
    nw := nw || jsonb_build_object('max_players', mp);
  end if;
  if p_settings ? 'default_perms' then
    if not public._valid_perms(p_settings->'default_perms') then return public._err('bad_perms'); end if;
    nw := nw || jsonb_build_object('default_perms', public._default_perms() || (p_settings->'default_perms'));
  end if;
  update public.rooms set settings = nw where id = p_room;
  return jsonb_build_object('ok', true, 'settings', nw);
end $$;

create or replace function public.regen_code(p_room uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u uuid := public._require_user(); c text; tries int := 0;
begin
  if not exists (select 1 from public.rooms where id = p_room and master_id = u and status = 'open') then
    return public._err('forbidden');
  end if;
  loop
    c := public._gen_code(10);
    begin
      update public.rooms set code = c where id = p_room;
      exit;
    exception when unique_violation then
      tries := tries + 1;
      if tries > 8 then return public._err('code_generation_failed'); end if;
    end;
  end loop;
  return jsonb_build_object('ok', true, 'code', c);
end $$;

create or replace function public.close_room(p_room uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user();
begin
  update public.rooms set status = 'closed', closed_at = now()
   where id = p_room and master_id = u and status = 'open';
  if not found then return public._err('forbidden'); end if;
  insert into public.room_chat(room_id, user_id, author, kind, body)
  values (p_room, null, 'Sala', 'system', 'A sala foi encerrada pelo Mestre.');
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- RPC: ficha (com controle de versão e permissões por categoria)
-- ---------------------------------------------------------------------
create or replace function public.push_sheet(p_room uuid, p_owner uuid, p_data jsonb, p_summary jsonb, p_base_rev int)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  u uuid := public._require_user();
  r public.rooms%rowtype; m public.room_members%rowtype; sh public.sheets%rowtype;
  is_m boolean; key_ text; sp record; nw jsonb; rejected text[] := '{}'; applied boolean := false; summ jsonb;
begin
  select * into r from public.rooms where id = p_room;
  if not found then return public._err('not_found'); end if;
  if r.status <> 'open' then return public._err('room_closed'); end if;
  is_m := (r.master_id = u);
  if not is_m and p_owner is distinct from u then return public._err('forbidden'); end if;
  select * into m from public.room_members where room_id = p_room and user_id = p_owner;
  if not found or m.status <> 'active' then return public._err('not_member'); end if;
  if not is_m then
    if not exists (select 1 from public.room_members where room_id = p_room and user_id = u and status = 'active') then
      return public._err('not_member');
    end if;
  end if;
  if p_data is null or jsonb_typeof(p_data) <> 'object' then return public._err('bad_data'); end if;
  if octet_length(p_data::text) > 262144 then return public._err('too_large'); end if;
  summ := coalesce(p_summary, '{}'::jsonb);
  if jsonb_typeof(summ) <> 'object' or octet_length(summ::text) > 4096 then return public._err('bad_summary'); end if;

  for key_ in select jsonb_object_keys(p_data) loop
    select s.k, s.cat, s.ty into sp from public._sheet_spec() s where s.k = key_;
    if not found then return public._err('unknown_key', jsonb_build_object('key', key_)); end if;
    if not (jsonb_typeof(p_data->key_) = any (string_to_array(sp.ty, '|'))) then
      return public._err('bad_type', jsonb_build_object('key', key_));
    end if;
    if jsonb_typeof(p_data->key_) = 'array' and jsonb_array_length(p_data->key_) > 1000 then
      return public._err('too_large', jsonb_build_object('key', key_));
    end if;
  end loop;

  select * into sh from public.sheets where room_id = p_room and owner_id = p_owner for update;
  if not found then
    -- primeiro envio (semeadura da ficha local): aceito integralmente
    insert into public.sheets(room_id, owner_id, data, summary, rev, updated_by)
    values (p_room, p_owner, p_data, summ, 1, u);
    return jsonb_build_object('ok', true, 'rev', 1, 'data', p_data, 'rejected', '[]'::jsonb);
  end if;

  if p_base_rev is distinct from sh.rev then
    return public._err('conflict', jsonb_build_object('rev', sh.rev, 'data', sh.data));
  end if;

  nw := sh.data;
  for key_ in select jsonb_object_keys(p_data) loop
    if (p_data->key_) is distinct from (sh.data->key_) then
      select s.cat into sp from public._sheet_spec() s where s.k = key_;
      if is_m or coalesce((m.perms->>sp.cat)::boolean, true) then
        nw := nw || jsonb_build_object(key_, p_data->key_);
        applied := true;
      else
        rejected := array_append(rejected, key_);
      end if;
    end if;
  end loop;

  if applied then
    update public.sheets set data = nw, summary = summ, rev = rev + 1, updated_by = u, updated_at = now()
     where room_id = p_room and owner_id = p_owner returning * into sh;
  elsif summ is distinct from sh.summary and array_length(rejected,1) is null then
    update public.sheets set summary = summ, updated_at = now()
     where room_id = p_room and owner_id = p_owner returning * into sh;
  end if;
  return jsonb_build_object('ok', true, 'rev', sh.rev, 'data', sh.data, 'rejected', to_jsonb(rejected));
end $$;

-- ---------------------------------------------------------------------
-- RPC: chat e eventos
-- ---------------------------------------------------------------------
create or replace function public.post_chat(p_room uuid, p_body text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user(); r public.rooms%rowtype; m public.room_members%rowtype;
        b text := btrim(coalesce(p_body,'')); nid bigint;
begin
  select * into r from public.rooms where id = p_room;
  if not found then return public._err('not_found'); end if;
  if r.status <> 'open' then return public._err('room_closed'); end if;
  select * into m from public.room_members where room_id = p_room and user_id = u and status = 'active';
  if not found then return public._err('not_member'); end if;
  if m.role = 'player' and not coalesce((m.perms->>'chat')::boolean, true) then return public._err('muted'); end if;
  b := regexp_replace(b, '[\x01-\x09\x0b-\x1f\x7f]', '', 'g');
  if b = '' or char_length(b) > 1000 then return public._err('bad_body'); end if;
  if (select count(*) from public.room_chat where room_id = p_room and user_id = u and created_at > now() - interval '10 seconds') >= 12 then
    return public._err('rate_limited');
  end if;
  insert into public.room_chat(room_id, user_id, author, kind, body)
  values (p_room, u, m.display_name, 'msg', b) returning id into nid;
  return jsonb_build_object('ok', true, 'id', nid);
end $$;

create or replace function public.post_event(p_room uuid, p_kind text, p_payload jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u uuid := public._require_user(); r public.rooms%rowtype; m public.room_members%rowtype; nid bigint;
begin
  if p_kind is null or p_kind not in ('roll','hp','cond') then return public._err('bad_kind'); end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' or octet_length(p_payload::text) > 4096 then
    return public._err('bad_payload');
  end if;
  select * into r from public.rooms where id = p_room;
  if not found then return public._err('not_found'); end if;
  if r.status <> 'open' then return public._err('room_closed'); end if;
  select * into m from public.room_members where room_id = p_room and user_id = u and status = 'active';
  if not found then return public._err('not_member'); end if;
  if m.role = 'player' and p_kind = 'roll' and not coalesce((m.perms->>'rolar')::boolean, true) then
    return public._err('forbidden');
  end if;
  if (select count(*) from public.room_events where room_id = p_room and user_id = u and created_at > now() - interval '10 seconds') >= 40 then
    return public._err('rate_limited');
  end if;
  insert into public.room_events(room_id, user_id, author, kind, payload)
  values (p_room, u, m.display_name, p_kind, p_payload) returning id into nid;
  return jsonb_build_object('ok', true, 'id', nid);
end $$;

create or replace function public.ping() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('ok', true, 'now', now(), 'uid', auth.uid())
$$;

-- Limpeza opcional de salas encerradas (rode manualmente ou via pg_cron; NÃO exposta ao cliente)
create or replace function public.purge_closed_rooms(p_days int default 30) returns int
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  delete from public.rooms where status = 'closed' and closed_at < now() - make_interval(days => p_days);
  get diagnostics n = row_count;
  return n;
end $$;

-- ---------------------------------------------------------------------
-- Privilégios
-- ---------------------------------------------------------------------
revoke all on all tables in schema public from anon, authenticated;
grant select on public.rooms, public.room_members, public.sheets, public.room_events, public.room_chat to authenticated;

do $$
declare f record;
begin
  for f in
    select p.oid::regprocedure as sig from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname in (
      '_require_user','_err','_clean_text','_gen_code','_perm_keys','_default_perms','_valid_perms','_sheet_spec','_default_settings',
      'is_member','is_room_master','room_shares_status','create_room','join_room','leave_room','kick_member','set_member_perms',
      'set_room_settings','regen_code','close_room','push_sheet','post_chat','post_event','ping','purge_closed_rooms')
  loop
    execute format('revoke all on function %s from public, anon, authenticated', f.sig);
  end loop;
end $$;

grant execute on function public.is_member(uuid), public.is_room_master(uuid), public.room_shares_status(uuid) to authenticated;
grant execute on function public.create_room(text,text), public.join_room(text,text), public.leave_room(uuid),
  public.kick_member(uuid,uuid), public.set_member_perms(uuid,uuid,jsonb), public.set_room_settings(uuid,jsonb),
  public.regen_code(uuid), public.close_room(uuid), public.push_sheet(uuid,uuid,jsonb,jsonb,int),
  public.post_chat(uuid,text), public.post_event(uuid,text,jsonb), public.ping() to authenticated;

-- ---------------------------------------------------------------------
-- Realtime (tabelas observadas pelos clientes; o RLS continua valendo)
-- ---------------------------------------------------------------------
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['rooms','room_members','sheets','room_events','room_chat'] loop
      if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;
