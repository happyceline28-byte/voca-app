-- 중국어 단어장 (voca-app) 데이터베이스 설정
-- Supabase 대시보드 > SQL Editor 에 전부 붙여 넣고 Run 하세요. (여러 번 실행해도 안전해요)

-- 1) 테이블 ---------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null unique check (username ~ '^[a-z0-9_]{3,12}$'),
  avatar     jsonb not null default '{"face":"🐱","bg":"#ffd9a8","acc":""}'::jsonb
             check (pg_column_size(avatar) < 300),
  best       int not null default 0,
  total      int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.word_lists (
  user_id uuid primary key references auth.users(id) on delete cascade,
  mine    text[] not null default '{}' check (cardinality(mine) <= 700)
);

create table if not exists public.friendships (
  user_id   uuid not null references public.profiles(id) on delete cascade,
  friend_id uuid not null references public.profiles(id) on delete cascade,
  primary key (user_id, friend_id),
  check (user_id <> friend_id)
);

-- 2) 새 회원이 가입하면 프로필과 단어장을 자동으로 만들어요 -------------------
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, username)
  values (new.id, lower(new.raw_user_meta_data->>'username'));
  insert into public.word_lists (user_id) values (new.id);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 3) 보안 규칙 (Row Level Security) ----------------------------------------
alter table public.profiles    enable row level security;
alter table public.word_lists  enable row level security;
alter table public.friendships enable row level security;

drop policy if exists "profiles: 로그인한 사람은 볼 수 있어요" on public.profiles;
create policy "profiles: 로그인한 사람은 볼 수 있어요"
  on public.profiles for select to authenticated using (true);

drop policy if exists "profiles: 내 것만 고쳐요" on public.profiles;
create policy "profiles: 내 것만 고쳐요"
  on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- 새 Supabase 프로젝트는 테이블 접근 권한을 자동으로 주지 않아서, 필요한 만큼만 직접 줘요
grant usage on schema public to authenticated;
grant select on public.profiles    to authenticated;
grant select on public.friendships to authenticated;
grant select, insert, update, delete on public.word_lists to authenticated;

-- 점수(best, total)는 직접 못 고치고 아바타만 고칠 수 있어요
revoke update on public.profiles from authenticated, anon;
grant  update (avatar) on public.profiles to authenticated;

drop policy if exists "word_lists: 내 단어장만" on public.word_lists;
create policy "word_lists: 내 단어장만"
  on public.word_lists for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "friendships: 내 친구만 봐요" on public.friendships;
create policy "friendships: 내 친구만 봐요"
  on public.friendships for select to authenticated using (user_id = auth.uid());
-- (친구 추가/삭제는 아래 함수로만 할 수 있어요)

-- 4) 함수 -------------------------------------------------------------------
-- 퀴즈 점수 저장: 0~100점, 10점 단위만 받아요
create or replace function public.submit_score(p_score int)
returns public.profiles language plpgsql security definer set search_path = public as $$
declare r public.profiles;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if p_score < 0 or p_score > 100 or p_score % 10 <> 0 then raise exception 'bad score'; end if;
  update public.profiles
     set best = greatest(best, p_score), total = total + p_score
   where id = auth.uid()
  returning * into r;
  return r;
end $$;

-- 친구 추가: 아이디로 찾아서 서로 친구로 연결해요
create or replace function public.add_friend(p_username text)
returns void language plpgsql security definer set search_path = public as $$
declare fid uuid;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  select id into fid from public.profiles where username = lower(p_username);
  if fid is null then raise exception 'not found'; end if;
  if fid = auth.uid() then raise exception 'self'; end if;
  insert into public.friendships (user_id, friend_id)
  values (auth.uid(), fid), (fid, auth.uid())
  on conflict do nothing;
end $$;

-- 친구 삭제
create or replace function public.remove_friend(p_friend uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from public.friendships
   where (user_id = auth.uid() and friend_id = p_friend)
      or (user_id = p_friend and friend_id = auth.uid());
end $$;

-- 내 계정 삭제: 로그인한 본인 계정만 지워요 (프로필, 단어장, 친구 연결도 같이 지워져요)
create or replace function public.delete_my_account()
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from auth.users where id = auth.uid();
end $$;

revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

revoke all on function public.submit_score(int)   from public, anon;
revoke all on function public.add_friend(text)    from public, anon;
revoke all on function public.remove_friend(uuid) from public, anon;
grant execute on function public.submit_score(int)   to authenticated;
grant execute on function public.add_friend(text)    to authenticated;
grant execute on function public.remove_friend(uuid) to authenticated;
