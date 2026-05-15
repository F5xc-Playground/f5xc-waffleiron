import { useState, useMemo, useCallback, useEffect } from 'react';
import type { AlarmOnlySignature, AlarmOnlyViolation, DecisionRequest } from '../types';

type SignatureAction = AlarmOnlySignature['action'];
type ViolationAction = AlarmOnlyViolation['action'];

interface SignatureRow {
  kind: 'signature';
  id: string;
  sig_id: number;
  description: string;
  scope: string;
  action: SignatureAction;
}

interface ViolationRow {
  kind: 'violation';
  id: string;
  violation_name: string;
  description: string;
  scope: string;
  action: ViolationAction;
}

type Row = SignatureRow | ViolationRow;

type SortField = 'type' | 'id' | 'description' | 'scope' | 'action';
type SortDir = 'asc' | 'desc';
type FilterType = 'all' | 'signatures' | 'violations';

interface DecisionsTableProps {
  signatures: AlarmOnlySignature[];
  violations: AlarmOnlyViolation[];
  onDecisionsChange: (decisions: DecisionRequest) => void;
}

function buildRows(signatures: AlarmOnlySignature[], violations: AlarmOnlyViolation[]): Row[] {
  const sigRows: SignatureRow[] = signatures.map((s) => ({
    kind: 'signature',
    id: `sig-${s.sig_id}`,
    sig_id: s.sig_id,
    description: s.description,
    scope: s.scope,
    action: s.action,
  }));
  const violRows: ViolationRow[] = violations.map((v) => ({
    kind: 'violation',
    id: `viol-${v.violation_name}`,
    violation_name: v.violation_name,
    description: v.violation_name,
    scope: '',
    action: v.action,
  }));
  return [...sigRows, ...violRows];
}

function rowBg(row: Row): string {
  switch (row.action) {
    case 'enforce':
      return 'bg-green-50 dark:bg-green-950/20';
    case 'defer':
      return 'bg-yellow-50 dark:bg-yellow-950/20';
    case 'exclude':
    case 'disable':
      return 'bg-red-50 dark:bg-red-950/20';
    default:
      return '';
  }
}

function getSortValue(row: Row, field: SortField): string | number {
  switch (field) {
    case 'type':
      return row.kind;
    case 'id':
      return row.kind === 'signature' ? row.sig_id : row.violation_name;
    case 'description':
      return row.description;
    case 'scope':
      return row.scope;
    case 'action':
      return row.action;
  }
}

export default function DecisionsTable({ signatures, violations, onDecisionsChange }: DecisionsTableProps) {
  const [rows, setRows] = useState<Row[]>(() => buildRows(signatures, violations));
  const [sortField, setSortField] = useState<SortField>('type');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [filter, setFilter] = useState<FilterType>('all');

  // Emit current decisions whenever rows change
  useEffect(() => {
    const sigDecisions = rows
      .filter((r): r is SignatureRow => r.kind === 'signature')
      .map((r) => ({ sig_id: r.sig_id, action: r.action }));
    const violDecisions = rows
      .filter((r): r is ViolationRow => r.kind === 'violation')
      .map((r) => ({ violation_name: r.violation_name, action: r.action }));

    onDecisionsChange({
      alarm_only_signatures: sigDecisions,
      alarm_only_violations: violDecisions.length > 0 ? violDecisions : undefined,
    });
  }, [rows, onDecisionsChange]);

  const handleSort = useCallback((field: SortField) => {
    setSortField((prev) => {
      if (prev === field) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        return prev;
      }
      setSortDir('asc');
      return field;
    });
  }, []);

  const updateRowAction = useCallback((id: string, newAction: string) => {
    setRows((prev) =>
      prev.map((r) => {
        if (r.id !== id) return r;
        if (r.kind === 'signature') return { ...r, action: newAction as SignatureAction };
        return { ...r, action: newAction as ViolationAction };
      }),
    );
  }, []);

  const bulkSetSignatures = useCallback((action: SignatureAction) => {
    setRows((prev) =>
      prev.map((r): Row => (r.kind === 'signature' ? { ...r, action } : r)),
    );
  }, []);

  const bulkSetViolations = useCallback((action: ViolationAction) => {
    setRows((prev) =>
      prev.map((r): Row => (r.kind === 'violation' ? { ...r, action } : r)),
    );
  }, []);

  const filtered = useMemo(() => {
    let result = rows;
    if (filter === 'signatures') result = result.filter((r) => r.kind === 'signature');
    if (filter === 'violations') result = result.filter((r) => r.kind === 'violation');
    return result;
  }, [rows, filter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      const aVal = getSortValue(a, sortField);
      const bVal = getSortValue(b, sortField);
      const cmp = typeof aVal === 'number' && typeof bVal === 'number'
        ? aVal - bVal
        : String(aVal).localeCompare(String(bVal));
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sortField, sortDir]);

  const headerClass = 'cursor-pointer select-none px-3 py-2 text-left text-xs font-medium uppercase tracking-wider text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200';
  const sortIndicator = (field: SortField) =>
    sortField === field ? (sortDir === 'asc' ? ' ↑' : ' ↓') : '';

  return (
    <div>
      {/* Toolbar */}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        {/* Filter tabs */}
        <div className="flex rounded-md border border-gray-300 text-sm dark:border-gray-600">
          {(['all', 'signatures', 'violations'] as const).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 capitalize first:rounded-l-md last:rounded-r-md ${
                filter === f
                  ? 'bg-indigo-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-50 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700'
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Bulk actions */}
        <div className="flex items-center gap-2 text-sm">
          <label className="text-gray-600 dark:text-gray-400">All signatures:</label>
          <select
            className="rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
            onChange={(e) => {
              if (e.target.value) bulkSetSignatures(e.target.value as SignatureAction);
              e.target.value = '';
            }}
            defaultValue=""
          >
            <option value="" disabled>Select...</option>
            <option value="exclude">Exclude</option>
            <option value="enforce">Enforce</option>
            <option value="defer">Defer</option>
          </select>
        </div>

        <div className="flex items-center gap-2 text-sm">
          <label className="text-gray-600 dark:text-gray-400">All violations:</label>
          <select
            className="rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
            onChange={(e) => {
              if (e.target.value) bulkSetViolations(e.target.value as ViolationAction);
              e.target.value = '';
            }}
            defaultValue=""
          >
            <option value="" disabled>Select...</option>
            <option value="disable">Disable</option>
            <option value="enforce">Enforce</option>
            <option value="defer">Defer</option>
          </select>
        </div>

        {/* Row count */}
        <span className="ml-auto text-xs text-gray-500 dark:text-gray-400">
          {sorted.length} item{sorted.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
        <table className="min-w-full divide-y divide-gray-200 text-sm dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className={headerClass} onClick={() => handleSort('type')}>
                Type{sortIndicator('type')}
              </th>
              <th className={headerClass} onClick={() => handleSort('id')}>
                ID{sortIndicator('id')}
              </th>
              <th className={headerClass} onClick={() => handleSort('description')}>
                Description{sortIndicator('description')}
              </th>
              <th className={headerClass} onClick={() => handleSort('scope')}>
                Scope{sortIndicator('scope')}
              </th>
              <th className={`${headerClass} w-36`} onClick={() => handleSort('action')}>
                Decision{sortIndicator('action')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-900">
            {sorted.map((row) => (
              <tr key={row.id} className={rowBg(row)}>
                <td className="whitespace-nowrap px-3 py-2 capitalize text-gray-700 dark:text-gray-300">
                  {row.kind}
                </td>
                <td className="whitespace-nowrap px-3 py-2 font-mono text-gray-900 dark:text-white">
                  {row.kind === 'signature' ? row.sig_id : row.violation_name}
                </td>
                <td className="px-3 py-2 text-gray-700 dark:text-gray-300">
                  {row.description}
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-gray-500 dark:text-gray-400">
                  {row.scope || '—'}
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <select
                    value={row.action}
                    onChange={(e) => updateRowAction(row.id, e.target.value)}
                    className="w-full rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
                  >
                    {row.kind === 'signature' ? (
                      <>
                        <option value="exclude">Exclude</option>
                        <option value="enforce">Enforce</option>
                        <option value="defer">Defer</option>
                      </>
                    ) : (
                      <>
                        <option value="disable">Disable</option>
                        <option value="enforce">Enforce</option>
                        <option value="defer">Defer</option>
                      </>
                    )}
                  </select>
                </td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-gray-400 dark:text-gray-500">
                  No items to display.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
