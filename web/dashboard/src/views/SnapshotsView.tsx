import { useEffect, useMemo, useState } from 'react';
import { Button, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { DatabaseBackup, GitCompareArrows, RotateCcw } from 'lucide-react';
import { api } from '../client';
import { AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { JsonBlock, KeyValue, KeyValueGrid, PanelHeader, StatusPill } from '../components';
import { formatDateTime, jsonPreview } from '../format';
import type { SnapshotCollectionDiff, SnapshotDiff, SnapshotMetadata } from '../types';

export function SnapshotsView({ canMutate }: { canMutate: boolean }) {
  const [snapshots, setSnapshots] = useState<SnapshotMetadata[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [fromVersion, setFromVersion] = useState('');
  const [toVersion, setToVersion] = useState('');
  const [diff, setDiff] = useState<SnapshotDiff | null>(null);
  const [rollbackTarget, setRollbackTarget] = useState<SnapshotMetadata | null>(null);
  const [reason, setReason] = useState('rollback policy snapshot');

  const load = async () => {
    try {
      setLoading(true);
      const next = await api.snapshots(false);
      setSnapshots(next);
      if (next.length >= 2 && (!fromVersion || !toVersion)) {
        setToVersion(String(next[0].version));
        setFromVersion(String(next[1].version));
      }
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load snapshots failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'version', headerName: 'Version', width: 110, valueFormatter: (value) => `v${value}` },
    { field: 'checksum', headerName: 'Checksum', flex: 1, minWidth: 220, valueFormatter: (value) => shortHash(String(value ?? '')) },
    { field: 'object_checksum', headerName: 'Object', flex: 1, minWidth: 220, valueFormatter: (value) => shortHash(String(value ?? '')) },
    { field: 'rollback_from', headerName: 'Rollback from', width: 130, valueFormatter: (value) => value ? `v${value}` : 'n/a' },
    { field: 'created_by', headerName: 'Created by', width: 170 },
    { field: 'created_at', headerName: 'Created', width: 185, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 160,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as SnapshotMetadata;
        return canMutate ? <Button size="small" variant="outlined" color="warning" onClick={() => {
          setRollbackTarget(row);
          setReason(`rollback to snapshot v${row.version}`);
        }}>Rollback</Button> : <span className="muted">read only</span>;
      }
    }
  ], [canMutate]);

  const loadDiff = async () => {
    try {
      const from = Number(fromVersion);
      const to = Number(toVersion);
      const next = await api.snapshotDiff(from, to);
      setDiff(next);
      setResult(`diff v${from} -> v${to} loaded`);
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'snapshot diff failed');
    }
  };

  const rollback = async () => {
    if (!rollbackTarget) return;
    try {
      await api.rollbackSnapshot(rollbackTarget.version, reason);
      setResult(`rollback snapshot v${rollbackTarget.version} created`);
      setRollbackTarget(null);
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'rollback failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader icon={<DatabaseBackup size={18} />} title="Snapshot Versions" eyebrow={`${snapshots.length} immutable versions`} />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={snapshots.map((item) => ({ ...item, id: item.version }))} columns={columns} loading={loading} emptyText="No snapshots created" height={390} />

      <section className="wide-panel">
        <PanelHeader icon={<GitCompareArrows size={18} />} title="Semantic Diff" eyebrow="services, whitelist, blacklist, rules" />
        <div className="snapshot-toolbar">
          <TextField select label="From" value={fromVersion} onChange={(event) => setFromVersion(event.target.value)}>
            {snapshots.map((snapshot) => <MenuItem key={snapshot.version} value={String(snapshot.version)}>v{snapshot.version}</MenuItem>)}
          </TextField>
          <TextField select label="To" value={toVersion} onChange={(event) => setToVersion(event.target.value)}>
            {snapshots.map((snapshot) => <MenuItem key={snapshot.version} value={String(snapshot.version)}>v{snapshot.version}</MenuItem>)}
          </TextField>
          <Button variant="contained" onClick={loadDiff} startIcon={<GitCompareArrows size={16} />}>Load diff</Button>
        </div>
        {diff ? <SnapshotDiffSummary diff={diff} /> : <p className="muted">No diff loaded</p>}
      </section>

      <ConfirmDialog
        open={Boolean(rollbackTarget)}
        title={`Rollback to v${rollbackTarget?.version ?? ''}`}
        confirmText="Create rollback"
        onCancel={() => setRollbackTarget(null)}
        onConfirm={rollback}
      >
        <Stack spacing={1.5}>
          <ReasonField value={reason} onChange={setReason} />
          <div className="muted"><RotateCcw size={14} /> Rollback creates a new snapshot from the selected version.</div>
        </Stack>
      </ConfirmDialog>
    </section>
  );
}

function SnapshotDiffSummary({ diff }: { diff: SnapshotDiff }) {
  return (
    <div className="snapshot-diff">
      <KeyValueGrid>
        <KeyValue label="From" value={`v${diff.from_version}`} />
        <KeyValue label="To" value={`v${diff.to_version}`} />
        <KeyValue label="Object checksum" value={<StatusPill state={diff.object_checksum.changed ? 'warn' : 'ok'} text={diff.object_checksum.changed ? 'changed' : 'same'} />} />
      </KeyValueGrid>
      <div className="diff-grid">
        <DiffCard title="Services" diff={diff.services} />
        <DiffCard title="Whitelist" diff={diff.whitelist_v4} />
        <DiffCard title="Blacklist" diff={diff.blacklist_v4} />
        <DiffCard title="Rules" diff={diff.rules} />
      </div>
      {diff.runtime ? (
        <section className="diff-card">
          <h3>Runtime</h3>
          <JsonBlock value={jsonPreview(diff.runtime)} />
        </section>
      ) : null}
    </div>
  );
}

function DiffCard({ title, diff }: { title: string; diff: SnapshotCollectionDiff }) {
  return (
    <section className="diff-card">
      <h3>{title}</h3>
      <KeyValueGrid>
        <KeyValue label="Added" value={String(diff.added.length)} />
        <KeyValue label="Removed" value={String(diff.removed.length)} />
        <KeyValue label="Changed" value={String(diff.changed.length)} />
        <KeyValue label="Unchanged" value={String(diff.unchanged)} />
      </KeyValueGrid>
      {diff.changed[0] ? <JsonBlock value={jsonPreview(diff.changed[0])} /> : null}
    </section>
  );
}

function shortHash(value: string): string {
  return value.length > 16 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value || 'n/a';
}
