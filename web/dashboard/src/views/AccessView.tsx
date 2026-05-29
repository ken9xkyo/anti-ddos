import { useEffect, useMemo, useState } from 'react';
import { Button, Checkbox, FormControlLabel, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { KeyRound, Plus, RotateCcw, ShieldCheck, Users } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, ConfirmDialog, InlineResult, ReasonField } from '../adminUi';
import { PanelHeader, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { Role, User } from '../types';

type UserForm = {
  reason: string;
  username: string;
  password: string;
  role: Role;
  status: string;
  force_password_change: boolean;
};

const emptyUserForm: UserForm = {
  reason: 'update user access',
  username: '',
  password: '',
  role: 'viewer',
  status: 'active',
  force_password_change: true
};

export function AccessView({ currentUser }: { currentUser: User }) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [mode, setMode] = useState<'create' | 'edit' | 'reset' | ''>('');
  const [target, setTarget] = useState<User | null>(null);
  const [form, setForm] = useState<UserForm>(emptyUserForm);
  const [revokeTarget, setRevokeTarget] = useState<User | null>(null);
  const [reason, setReason] = useState('revoke user sessions');
  const isAdmin = currentUser.role === 'admin';

  const load = async () => {
    try {
      setLoading(true);
      setUsers(await api.users());
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load users failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'username', headerName: 'Username', flex: 1, minWidth: 150 },
    { field: 'role', headerName: 'Role', width: 120 },
    {
      field: 'status',
      headerName: 'Status',
      width: 125,
      renderCell: (params) => <StatusPill state={params.value === 'active' ? 'ok' : 'off'} text={params.value || 'active'} />
    },
    {
      field: 'force_password_change',
      headerName: 'Force change',
      width: 130,
      valueGetter: (_, row) => row.force_password_change ? 'yes' : 'no'
    },
    { field: 'last_login_at', headerName: 'Last login', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'created_at', headerName: 'Created', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 220,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as User;
        if (!isAdmin) return <span className="muted">read only</span>;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" onClick={() => openReset(row)}>Reset</Button>
            <Button size="small" variant="outlined" color="warning" onClick={() => {
              setRevokeTarget(row);
              setReason(`revoke ${row.username} sessions`);
            }}>Sessions</Button>
          </Stack>
        );
      }
    }
  ], [isAdmin]);

  const openCreate = () => {
    setTarget(null);
    setForm({ ...emptyUserForm, reason: 'create user' });
    setMode('create');
  };

  const openEdit = (user: User) => {
    setTarget(user);
    setForm({
      ...emptyUserForm,
      reason: `update ${user.username}`,
      username: user.username,
      role: user.role,
      status: user.status ?? 'active',
      force_password_change: Boolean(user.force_password_change)
    });
    setMode('edit');
  };

  const openReset = (user: User) => {
    setTarget(user);
    setForm({ ...emptyUserForm, reason: `reset ${user.username} password`, username: user.username, role: user.role });
    setMode('reset');
  };

  const submit = async () => {
    if (!isAdmin) return;
    try {
      if (mode === 'create') {
        await api.createUser({ reason: form.reason, username: form.username, password: form.password, role: form.role });
        setResult(`${form.username} created`);
      } else if (mode === 'edit' && target) {
        await api.updateUser(target.id, {
          reason: form.reason,
          role: form.role,
          status: form.status,
          force_password_change: form.force_password_change
        });
        setResult(`${target.username} updated`);
      } else if (mode === 'reset' && target) {
        await api.resetUserPassword(target.id, {
          reason: form.reason,
          password: form.password,
          force_password_change: form.force_password_change
        });
        setResult(`${target.username} password reset`);
      }
      setMode('');
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'user mutation failed');
    }
  };

  const revokeSessions = async () => {
    if (!revokeTarget) return;
    try {
      await api.revokeUserSessions(revokeTarget.id, reason);
      setResult(`${revokeTarget.username} sessions revoked`);
      setRevokeTarget(null);
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'session revoke failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Users size={18} />}
          title="User Management"
          eyebrow="local RBAC"
          actions={isAdmin ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add user</button> : null}
        />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={users} columns={columns} loading={loading} emptyText="No local users" height={520} />

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'create' ? 'Add User' : mode === 'reset' ? `Reset ${target?.username ?? 'user'} Password` : `Edit ${target?.username ?? 'user'}`}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={mode === 'reset' ? <KeyRound size={16} /> : <ShieldCheck size={16} />}>Save</Button>
        </>}
      >
        {mode === 'create' ? <TextField label="Username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} fullWidth required /> : null}
        {mode === 'create' || mode === 'reset' ? <TextField label="Temporary password" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} fullWidth required /> : null}
        {mode !== 'reset' ? (
          <>
            <TextField select label="Role" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value as Role })} fullWidth>
              <MenuItem value="viewer">Viewer</MenuItem>
              <MenuItem value="operator">Operator</MenuItem>
              <MenuItem value="admin">Admin</MenuItem>
            </TextField>
            <TextField select label="Status" value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })} fullWidth>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="revoked">Revoked</MenuItem>
            </TextField>
          </>
        ) : null}
        <FormControlLabel control={<Checkbox checked={form.force_password_change} onChange={(event) => setForm({ ...form, force_password_change: event.target.checked })} />} label="Force password change" />
        <ReasonField value={form.reason} onChange={(value) => setForm({ ...form, reason: value })} />
      </AdminDrawer>

      <ConfirmDialog
        open={Boolean(revokeTarget)}
        title={`Revoke ${revokeTarget?.username ?? 'user'} Sessions`}
        confirmText="Revoke sessions"
        onCancel={() => setRevokeTarget(null)}
        onConfirm={revokeSessions}
      >
        <Stack spacing={1.5}>
          <ReasonField value={reason} onChange={setReason} />
          <div className="muted"><RotateCcw size={14} /> Active sessions for this user will be invalidated.</div>
        </Stack>
      </ConfirmDialog>
    </section>
  );
}
