-- ============================================================================
--  LAB-ONLY seed schema for the intentionally vulnerable API.
--  Passwords are stored in plaintext ON PURPOSE to demonstrate data exposure.
-- ============================================================================

create table if not exists users (
  id       serial primary key,
  username text not null unique,
  password text not null,           -- VULN: plaintext password storage
  email    text,
  role     text not null default 'user',
  api_key  text                     -- VULN: secret column returned by SELECT *
);

create table if not exists products (
  id    serial primary key,
  name  text not null,
  price numeric not null default 0
);

insert into users (username, password, email, role, api_key) values
  ('admin', 'admin123', 'admin@lab.test', 'admin', 'sk_live_lab_admin_key'),
  ('alice', 'password1', 'alice@lab.test', 'user',  'sk_live_lab_alice_key'),
  ('bob',   'hunter2',   'bob@lab.test',   'user',  'sk_live_lab_bob_key')
on conflict (username) do nothing;

insert into products (name, price) values
  ('Widget', 9.99),
  ('Gadget', 19.99)
on conflict do nothing;
