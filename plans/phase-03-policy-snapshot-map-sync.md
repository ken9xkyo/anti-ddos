# Phase 03 - Policy Snapshot va Map Sync

## Muc tieu

Thiet ke va implement luong apply immutable policy snapshot vao eBPF maps mot cach atomic: validate checksum/version/capacity, populate inactive slot, populate `tx_devmap`, flip `runtime_config`, ack thanh cong hoac giu policy cu khi loi.

## Pham vi

- Snapshot la canonical JSON co version tang dan va checksum.
- Agent validate feature flags, TTL, map capacity, memory estimate, DEVMAP target va compatibility voi XDP object.
- Policy maps can atomic replacement dung A/B double-buffer: whitelist, blacklist, service allowlist, rule config.
- Shared maps nhu `tx_devmap`, rate state, counters, events khong clear tuy tien; update co validate va rollback theo snapshot.
- Control API day du nam o Phase 05; phase nay co local/mock snapshot builder de test map sync.

## Cong viec

| ID | Cong viec | Muc dich | Ket qua ban giao | Phu thuoc |
|---|---|---|---|---|
| P03-T01 | Dinh nghia snapshot schema canonical | Lam hop dong chung giua API va Agent | JSON schema cho version, checksum, rules, whitelist, blacklist, services, xdp_config | Phase 02 |
| P03-T02 | Implement checksum canonical | Phat hien snapshot bi sua/hong | Canonical encoder va SHA checksum verifier | P03-T01 |
| P03-T03 | Implement version va compatibility checks | Tranh apply snapshot cu hoac khong support | Validation version monotonic, feature flags, object version | P03-T02 |
| P03-T04 | Implement capacity va memory estimator | Tranh map day hoac memory vuot budget | Estimator entries/memory cho LPM, service, rules, runtime, devmap | P03-T01 |
| P03-T05 | Validate service redirect target input | Chan snapshot co route/ifindex/MAC khong hop le | Checks output ifindex, devmap key, resolved MAC, neighbor status | P03-T04 |
| P03-T06 | Implement inactive-slot clear/populate | Khong lo policy partial tren hot path | Map writer cho whitelist/blacklist/service/rules inactive slot | P03-T05 |
| P03-T07 | Populate `tx_devmap` safely | Dam bao redirect target san sang truoc runtime flip | Devmap updater voi output ifindex va failure reason | P03-T05 |
| P03-T08 | Implement runtime flip | Chuyen policy atomic trong XDP | Update `runtime_config[0]` active slot va policy version | P03-T06, P03-T07 |
| P03-T09 | Implement failure rollback cho inactive slot | Loi populate khong anh huong active slot | Clear inactive slot, report failure, giu current policy | P03-T06 |
| P03-T10 | Persist local last-valid snapshot sau apply | Ho tro restart fail-safe | Local snapshot store chi ghi sau runtime flip success | P03-T08 |
| P03-T11 | Implement apply ack/failure payload | Control Plane biet trang thai apply | Ack co version, status, map stats, redirect stats, error reason | P03-T09 |
| P03-T12 | Test whitelist/blacklist precedence input | Dam bao whitelist precedence truoc blacklist/rate limit | Snapshot fixture conflict va expected active maps | P03-T06 |

## Tieu chi chap nhan

- Snapshot sai checksum, version cu, unsupported feature, redirect target sai hoac vuot capacity bi reject truoc khi ghi active policy.
- Loi khi populate inactive slot hoac `tx_devmap` khong doi active slot va khong doi packet decision.
- Runtime flip chi thuc hien sau khi tat ca inactive policy maps va redirect targets validate/populate thanh cong.
- Last-valid snapshot chi duoc persist sau apply thanh cong.
- Apply ack/failure co reason du de dashboard/API hien thi va audit.
- Whitelist precedence duoc encode trong effective snapshot hoac XDP decision order dung thiet ke.

## Kiem chung

- Unit test checksum canonical voi JSON field order khac nhau nhung noi dung giong nhau.
- Unit test reject snapshot vuot `blacklist_lpm`, `service_allowlist`, `rule_config`, `tx_devmap` capacity.
- Integration test populate fail giua chung va xac nhan `runtime_config.active_slot` khong doi.
- Integration test missing/invalid devmap target va unresolved neighbor bi reject hoac apply fail ro reason.
- Restart Agent sau apply thanh cong, xac nhan load local last-valid snapshot va active version dung.
- Packet test whitelist conflict blacklist: source trong whitelist van bypass blacklist/rate-limit nhung khong bypass service allowlist.

## Truy vet PRD

- PRD-004: rule TTL va rollback lifecycle can snapshot versioning.
- PRD-005: blacklist effective set apply qua snapshot.
- PRD-006: whitelist precedence va expiry input.
- PRD-007: service allowlist va DEVMAP target apply without restart.
- PRD-009: policy versioning lam nen tang rollback/audit.
- PRD-010: keep-last-policy fail-safe.

## Ghi chu va rui ro

- XDP khong nen phu thuoc wall-clock expiry neu khong co time source dang tin; Control Plane va Agent remove expired entries khi build snapshot.
- Double-buffer clear old slot nen thuc hien sau ack success hoac async de giam thoi gian apply.
- LPM trie va `rate_state` capacity lon can validate locked memory va kernel limits.
- Partial apply strategy duy nhat duoc chap nhan trong MVP la reject va giu policy cu.

