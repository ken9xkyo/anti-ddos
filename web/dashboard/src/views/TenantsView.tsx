import { useEffect, useMemo, useState } from 'react';
import { Button, MenuItem, Stack, TextField } from '@mui/material';
import { GridColDef } from '@mui/x-data-grid';
import { Building2, Plus, Users } from 'lucide-react';
import { api } from '../client';
import { AdminDrawer, AdminGrid, InlineResult } from '../adminUi';
import { PanelHeader, StatusPill } from '../components';
import { formatDateTime } from '../format';
import type { TenantAccess, TenantInput, User } from '../types';

type TenantForm = {
  slug: string;
  name: string;
  status: string;
};

const emptyTenantForm: TenantForm = {
  slug: '',
  name: '',
  status: 'active'
};

export function TenantsView({
  currentUser,
  onTenantSwitch,
  onOpenAccounts
}: {
  currentUser: User;
  onTenantSwitch?: (tenantID: string) => void | Promise<void>;
  onOpenAccounts: () => void;
}) {
  const [tenants, setTenants] = useState<TenantAccess[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');
  const [mode, setMode] = useState<'create' | 'edit' | ''>('');
  const [target, setTarget] = useState<TenantAccess | null>(null);
  const [form, setForm] = useState<TenantForm>(emptyTenantForm);
  const isPlatformAdmin = currentUser.platform_role === 'platform_admin';

  const load = async () => {
    if (!isPlatformAdmin) return;
    try {
      setLoading(true);
      setTenants(await api.tenants(true));
      setResult('');
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'load tenants failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [isPlatformAdmin]);

  const columns = useMemo<GridColDef[]>(() => [
    { field: 'slug', headerName: 'Slug', flex: 1, minWidth: 160 },
    { field: 'name', headerName: 'Name', flex: 1.3, minWidth: 190 },
    {
      field: 'status',
      headerName: 'Status',
      width: 125,
      renderCell: (params) => <StatusPill state={params.value === 'active' ? 'ok' : 'off'} text={params.value || 'active'} />
    },
    { field: 'role', headerName: 'Effective role', width: 135 },
    { field: 'created_at', headerName: 'Created', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    { field: 'updated_at', headerName: 'Updated', width: 180, valueFormatter: (value) => formatDateTime(value as string | undefined) },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 220,
      sortable: false,
      renderCell: (params) => {
        const row = params.row as TenantAccess;
        return (
          <Stack direction="row" spacing={0.75}>
            <Button size="small" variant="outlined" onClick={() => openEdit(row)}>Edit</Button>
            <Button size="small" variant="outlined" disabled={row.status !== 'active' || !onTenantSwitch} onClick={() => openAccounts(row)}>
              Accounts
            </Button>
          </Stack>
        );
      }
    }
  ], [onTenantSwitch]);

  const openCreate = () => {
    setTarget(null);
    setForm(emptyTenantForm);
    setMode('create');
  };

  const openEdit = (tenant: TenantAccess) => {
    setTarget(tenant);
    setForm({ slug: tenant.slug, name: tenant.name, status: tenant.status || 'active' });
    setMode('edit');
  };

  const openAccounts = async (tenant: TenantAccess) => {
    if (!onTenantSwitch || tenant.status !== 'active') return;
    try {
      await onTenantSwitch(tenant.tenant_id);
      onOpenAccounts();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'tenant switch failed');
    }
  };

  const submit = async () => {
    try {
      const input: TenantInput = {
        slug: form.slug.trim(),
        name: form.name.trim(),
        status: form.status
      };
      if (mode === 'edit' && target) {
        await api.updateTenant(target.tenant_id, { name: input.name, status: input.status });
        setResult(`${target.slug} updated`);
      } else {
        const created = await api.createTenant(input);
        setResult(`${created.slug} created`);
      }
      setMode('');
      await load();
    } catch (err) {
      setResult(err instanceof Error ? err.message : 'tenant mutation failed');
    }
  };

  return (
    <section className="content-stack">
      <section className="wide-panel">
        <PanelHeader
          icon={<Building2 size={18} />}
          title="Tenants"
          eyebrow="platform RBAC"
          actions={isPlatformAdmin ? <button type="button" className="primary-action" onClick={openCreate}><Plus size={15} />Add tenant</button> : null}
        />
        <InlineResult result={result} />
      </section>

      <AdminGrid rows={tenants} columns={columns} loading={loading} emptyText="No tenants" height={520} getRowId={(row) => row.tenant_id} />

      <AdminDrawer
        open={mode !== ''}
        title={mode === 'edit' ? `Edit ${target?.slug ?? 'Tenant'}` : 'Add Tenant'}
        onClose={() => setMode('')}
        actions={<>
          <Button onClick={() => setMode('')}>Cancel</Button>
          <Button variant="contained" onClick={submit} startIcon={mode === 'edit' ? <Building2 size={16} /> : <Users size={16} />}>Save</Button>
        </>}
      >
        {mode === 'create' ? <TextField label="Slug" value={form.slug} onChange={(event) => setForm({ ...form, slug: event.target.value })} fullWidth required /> : null}
        <TextField label="Name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} fullWidth required />
        <TextField select label="Status" value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value })} fullWidth>
          <MenuItem value="active">Active</MenuItem>
          <MenuItem value="revoked">Revoked</MenuItem>
        </TextField>
      </AdminDrawer>
    </section>
  );
}
