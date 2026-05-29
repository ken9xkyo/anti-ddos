import { ReactNode } from 'react';
import {
  Alert,
  Box,
  Button,
  Stack,
  TextField,
  Typography
} from '@mui/material';
import { DataGrid, GridColDef, GridRowsProp } from '@mui/x-data-grid';

export function AdminGrid({
  rows,
  columns,
  loading,
  emptyText = 'No rows',
  height = 430
}: {
  rows: GridRowsProp;
  columns: GridColDef[];
  loading?: boolean;
  emptyText?: string;
  height?: number;
}) {
  return (
    <Box className="mui-grid-shell" sx={{ height, minHeight: height, width: '100%' }}>
      <DataGrid
        rows={rows}
        columns={columns}
        loading={loading}
        disableRowSelectionOnClick
        pageSizeOptions={[10, 25, 50]}
        initialState={{ pagination: { paginationModel: { pageSize: 10, page: 0 } } }}
        density="compact"
        localeText={{ noRowsLabel: emptyText }}
        sx={{
          border: '1px solid rgba(148, 163, 184, 0.18)',
          '& .MuiDataGrid-columnHeaders': { backgroundColor: 'rgba(15, 23, 42, 0.76)' },
          '& .MuiDataGrid-cell': { outline: 'none !important' }
        }}
      />
    </Box>
  );
}

export function AdminDrawer({
  open,
  title,
  children,
  onClose,
  actions
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  onClose: () => void;
  actions?: ReactNode;
}) {
  if (!open) return null;
  return (
    <div className="drawer-layer" role="presentation">
      <button type="button" className="drawer-scrim" aria-label="close drawer" onClick={onClose} />
      <Box component="section" className="admin-drawer">
        <Typography variant="h6">{title}</Typography>
        <Stack spacing={1.5}>{children}</Stack>
        {actions ? (
          <Stack direction="row" spacing={1} className="drawer-actions" sx={{ justifyContent: 'flex-end' }}>
            {actions}
          </Stack>
        ) : null}
      </Box>
    </div>
  );
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmText = 'Confirm',
  busy,
  onCancel,
  onConfirm
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmText?: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  if (!open) return null;
  return (
    <div className="confirm-layer">
      <section className="confirm-dialog" role="dialog" aria-modal="true" aria-label={title}>
        <Typography variant="h6">{title}</Typography>
        <div className="confirm-content">{children}</div>
        <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end' }}>
          <Button onClick={onCancel} disabled={busy}>Cancel</Button>
          <Button onClick={onConfirm} variant="contained" color="warning" disabled={busy}>{busy ? 'Working' : confirmText}</Button>
        </Stack>
      </section>
    </div>
  );
}

export function ReasonField({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return <TextField label="Reason" value={value} onChange={(event) => onChange(event.target.value)} fullWidth required />;
}

export function JsonTextField({
  label,
  value,
  onChange
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="json-textarea-field">
      <span>{label}</span>
      <textarea value={value} onChange={(event) => onChange(event.target.value)} rows={4} spellCheck={false} />
    </label>
  );
}

export function InlineResult({ result }: { result: string }) {
  if (!result) return null;
  const tone = /failed|required|invalid|error|must|denied/i.test(result) ? 'error' : 'success';
  return <Alert severity={tone} variant="outlined">{result}</Alert>;
}

export function parseJsonObject(value: string): Record<string, unknown> | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = JSON.parse(trimmed);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('JSON value must be an object');
  }
  return parsed as Record<string, unknown>;
}
