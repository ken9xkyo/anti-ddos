import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';
import React from 'react';

vi.mock('@mui/x-data-grid', () => ({
  DataGrid: ({ rows, columns }: any) => {
    return React.createElement(
      'table',
      null,
      React.createElement(
        'thead',
        null,
        React.createElement(
          'tr',
          null,
          columns.map((c: any) =>
            React.createElement('th', { key: c.field }, c.headerName)
          )
        )
      ),
      React.createElement(
        'tbody',
        null,
        rows.map((r: any, idx: number) => {
          const rowId = r.id || String(idx);
          return React.createElement(
            'tr',
            { key: rowId, className: 'MuiDataGrid-row' },
            columns.map((c: any) => {
              let val = r[c.field];
              if (c.valueGetter) {
                val = c.valueGetter(val, r);
              }
              let displayVal = val;
              if (c.valueFormatter) {
                displayVal = c.valueFormatter(val);
              }
              return React.createElement(
                'td',
                { key: c.field },
                c.renderCell
                  ? c.renderCell({ value: val, row: r })
                  : String(displayVal ?? '')
              );
            })
          );
        })
      )
    );
  }
}));


