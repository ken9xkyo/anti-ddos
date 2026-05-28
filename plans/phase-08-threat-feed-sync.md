# Phase 08 - Threat Feed Sync

## Muc tieu

Dong bo IP/CIDR reputation feeds bat buoc cho P1, normalize/dedupe/aggregate an toan, tao conflict report voi whitelist va dua effective blacklist vao policy snapshot moi moi 1 gio hoac theo interval cau hinh.

## Pham vi

- Scheduler theo source interval, default 1 gio.
- Feed source metadata: URL, enabled, interval, license/quota note, secret ref, last status.
- Parser cho Spamhaus DROP, Team Cymru/bogon, AbuseIPDB va internal HTTP JSON.
- Safe CIDR aggregation chi merge khi cung source/action/score/TTL va khong co whitelist conflict trong prefix rong hon.
- Feed failure giu last valid source snapshot va alert neu loi keo dai.
- AbuseIPDB key va feed secrets khong log plaintext.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P08-T01 | Implement feed source schema/API | Quan ly nguon reputation | `feed_sources`, CRUD config, secret ref, interval, license note | Phase 05 |
| P08-T02 | Implement scheduler va locking | Chay sync dung chu ky, khong overlap | Hourly scheduler, per-source run lock, run status | P08-T01 |
| P08-T03 | Implement fetch client timeout/retry | Khong treo scheduler khi feed loi | HTTP clients voi timeout, auth header tu secret ref | P08-T02 |
| P08-T04 | Implement Spamhaus DROP parser | Dua Spamhaus vao blacklist | Parser plain text CIDR, comments, source metadata | P08-T03 |
| P08-T05 | Implement Team Cymru/bogon parser | Dua bogon/invalid source vao blacklist | Parser CIDR/bogon feed, source metadata | P08-T03 |
| P08-T06 | Implement AbuseIPDB parser/client | Dua reputation API vao pipeline | Client/parser theo config quota, score, TTL | P08-T03 |
| P08-T07 | Implement internal HTTP JSON parser | Ho tro feed noi bo | Parser IP/CIDR, score, action, TTL, reason, source metadata | P08-T03 |
| P08-T08 | Implement normalize/dedupe | Loai duplicate va invalid entries | CIDR validation IPv4, source metadata, score/action/TTL | P08-T04, P08-T05, P08-T06, P08-T07 |
| P08-T09 | Implement safe CIDR aggregation | Giam map entries khong broaden sai | Aggregator chi merge khi source/action/score/TTL safe | P08-T08 |
| P08-T10 | Implement whitelist conflict report | Giu whitelist precedence | `feed_conflicts`, suppressed entries, UI/API output | P08-T09 |
| P08-T11 | Build effective blacklist snapshot | Dua reputation vao XDP maps | Snapshot builder include blacklist minus whitelist-suppressed conflicts | P08-T10 |
| P08-T12 | Implement feed failure behavior | Khong xoa rule dang enforce khi loi | Keep last valid, record `feed_runs`, alert candidate | P08-T02 |
| P08-T13 | Add feed UI/metrics | Operator thay last sync/errors/quota | Dashboard feed status va Prometheus feed metrics | Phase 06 |

## Tieu chi chap nhan

- Scheduler sync enabled feeds theo interval cau hinh, default 1 gio.
- Invalid IP/CIDR bi reject co parse error count, khong lam fail ca run neu con entries hop le.
- Duplicate CIDR duoc dedupe, adjacent CIDR chi aggregate khi safe.
- Entry conflict whitelist khong duoc enforce trong effective blacklist va co conflict report.
- Feed failure giu last valid snapshot va khong xoa blacklist dang enforce neu chua co snapshot moi hop le.
- Feed status, items fetched, errors, active entries va conflicts hien tren metrics/dashboard.

## Kiem chung

- Fixture tests cho Spamhaus DROP, Team Cymru/bogon, AbuseIPDB va internal feed.
- Aggregation tests cho merge safe va khong merge khi TTL/source/score khac hoac co whitelist inside.
- Failure tests cho timeout, invalid auth, malformed payload, partial invalid entries.
- Snapshot diff test xac nhan chi build version moi khi effective set thay doi.
- UI/API test xac nhan conflict report va feed run history.

## Truy vet PRD

- PRD-005: IP reputation va blacklist aggregation moi 1 gio.
- PRD-006: whitelist precedence va conflict report.
- PRD-008: feed failure canh bao qua alert pipeline sau Phase 09.
- PRD-009: feed config changes co audit.
- PRD-010: feed failure giu last valid snapshot.

## Ghi chu va rui ro

- Feed license/quota/update interval phai duoc luu va ton trong; khong hard-code goi qua tan suat cho phep.
- CIDR aggregation sai co the block rong hon y dinh; neu uncertain thi giu prefix hep.
- AbuseIPDB co quota/API semantics thay doi theo account; can cau hinh timeout va rate limit rieng.
- Feed secrets phai dung secret ref/encrypted storage, khong dua vao audit diff plaintext.

