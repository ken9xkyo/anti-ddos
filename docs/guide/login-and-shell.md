# Login Và Shell

Tat ca user dang nhap bang `username` va `password`. Response user chi co role `admin` hoac `user`; khong co tenant fields.

## Shell

- Sidebar gom `Operation`, `Configuration` va `Setting`.
- `Operation`: Dashboard, Incidents, Detections, Events.
- `Configuration`: Services, Rules, Whitelist, Blacklist, UDP Ports.
- `Setting`: Snapshots, Accounts, Nodes.
- `Accounts` chi hien voi admin.
- Topbar hien `username · role`; khi admin xem config user, topbar hien them `viewing <username> · read only`.

Dashboard polling khong goi tenant hoac feed endpoints.

## Read-only context

Admin dung `Accounts -> View config` de mo dashboard read-only cua user. UI khong render mutation controls va backend chan mutation config voi `403`.
