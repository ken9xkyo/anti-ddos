# Login Và Shell

Tat ca user dang nhap bang `username` va `password`. Response user chi co role `admin` hoac `user`; khong co tenant fields.

## Shell

- Sidebar gom `Operation`, `Configuration` va `Setting`.
- `Operation`: Dashboard, Incidents, Events.
- `Configuration`: Services, Rules, Whitelist, Blacklist, Reputation, UDP Ports.
- `Setting`: Snapshots, Accounts, Nodes.
- `Accounts` chi hien voi admin.
- `Reputation` chi hien voi admin normal session.
- Topbar hien `username · role`; khi admin xem config user, topbar hien them `viewing <username> · read only`.

Dashboard polling khong goi tenant endpoints. Chi admin normal session goi feed endpoints; user va admin view-user context khong goi `/v1/feed-*`.

## Read-only context

Admin dung `Accounts -> View config` de mo dashboard read-only cua user. UI khong render mutation controls va backend chan mutation config voi `403`.
