import { useState, useCallback, useEffect } from 'react';
import type { AlarmOnlySignature, AlarmOnlyViolation, DecisionRequest } from '../types';

type SignatureAction = 'exclude' | 'enforce';
type ViolationAction = 'disable' | 'enforce';

interface SigRow {
  sig_id: number;
  description: string;
  scope: string;
  action: SignatureAction;
}

interface ViolRow {
  violation_name: string;
  action: ViolationAction;
}

interface DecisionsTableProps {
  signatures: AlarmOnlySignature[];
  violations: AlarmOnlyViolation[];
  onDecisionsChange: (decisions: DecisionRequest) => void;
}

function normalizeSigAction(action: string): SignatureAction {
  return action === 'enforce' ? 'enforce' : 'exclude';
}

function normalizeViolAction(action: string): ViolationAction {
  return action === 'enforce' ? 'enforce' : 'disable';
}

export default function DecisionsTable({ signatures, violations, onDecisionsChange }: DecisionsTableProps) {
  const [sigRows, setSigRows] = useState<SigRow[]>(() =>
    signatures.map((s) => ({
      sig_id: s.sig_id,
      description: s.description,
      scope: s.scope,
      action: normalizeSigAction(s.action),
    })),
  );

  const [violRows, setViolRows] = useState<ViolRow[]>(() =>
    violations.map((v) => ({
      violation_name: v.violation_name,
      action: normalizeViolAction(v.action),
    })),
  );

  useEffect(() => {
    onDecisionsChange({
      alarm_only_signatures: sigRows.map((r) => ({ sig_id: r.sig_id, action: r.action })),
      alarm_only_violations: violRows.length > 0
        ? violRows.map((r) => ({ violation_name: r.violation_name, action: r.action }))
        : undefined,
    });
  }, [sigRows, violRows, onDecisionsChange]);

  const updateSig = useCallback((sigId: number, action: SignatureAction) => {
    setSigRows((prev) => prev.map((r) => (r.sig_id === sigId ? { ...r, action } : r)));
  }, []);

  const updateViol = useCallback((name: string, action: ViolationAction) => {
    setViolRows((prev) => prev.map((r) => (r.violation_name === name ? { ...r, action } : r)));
  }, []);

  const bulkSetSigs = useCallback((action: SignatureAction) => {
    setSigRows((prev) => prev.map((r) => ({ ...r, action })));
  }, []);

  const bulkSetViols = useCallback((action: ViolationAction) => {
    setViolRows((prev) => prev.map((r) => ({ ...r, action })));
  }, []);

  const thClass = 'px-3 py-2 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400';

  return (
    <div className="space-y-6">
      {/* Signatures section */}
      {sigRows.length > 0 && (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
              Signatures
              <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                {sigRows.length} alarm-only
              </span>
            </h3>
            <div className="flex items-center gap-2 text-sm">
              <label className="text-gray-600 dark:text-gray-400">Set all:</label>
              <select
                className="rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
                onChange={(e) => {
                  if (e.target.value) bulkSetSigs(e.target.value as SignatureAction);
                  e.target.value = '';
                }}
                defaultValue=""
              >
                <option value="" disabled>Select...</option>
                <option value="exclude">Exclude</option>
                <option value="enforce">Enforce</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
            <table className="min-w-full divide-y divide-gray-200 text-sm dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className={thClass}>ID</th>
                  <th className={thClass}>Scope</th>
                  <th className={`${thClass} w-32`}>Decision</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-900">
                {sigRows.map((row) => (
                  <tr key={`${row.sig_id}-${row.scope}`}>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-gray-900 dark:text-white">
                      {row.sig_id}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-gray-700 dark:text-gray-300">
                      <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-700">{row.scope}</code>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <select
                        value={row.action}
                        onChange={(e) => updateSig(row.sig_id, e.target.value as SignatureAction)}
                        className="w-full rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
                      >
                        <option value="exclude">Exclude</option>
                        <option value="enforce">Enforce</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Violations section */}
      {violRows.length > 0 && (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
              Violations
              <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                {violRows.length} alarm-only
              </span>
            </h3>
            <div className="flex items-center gap-2 text-sm">
              <label className="text-gray-600 dark:text-gray-400">Set all:</label>
              <select
                className="rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
                onChange={(e) => {
                  if (e.target.value) bulkSetViols(e.target.value as ViolationAction);
                  e.target.value = '';
                }}
                defaultValue=""
              >
                <option value="" disabled>Select...</option>
                <option value="disable">Disable</option>
                <option value="enforce">Enforce</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
            <table className="min-w-full divide-y divide-gray-200 text-sm dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className={thClass}>Violation</th>
                  <th className={`${thClass} w-32`}>Decision</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-900">
                {violRows.map((row) => (
                  <tr key={row.violation_name}>
                    <td className="px-3 py-2 font-mono text-gray-900 dark:text-white">
                      {row.violation_name}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <select
                        value={row.action}
                        onChange={(e) => updateViol(row.violation_name, e.target.value as ViolationAction)}
                        className="w-full rounded border border-gray-300 bg-white px-2 py-1 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-200"
                      >
                        <option value="disable">Disable</option>
                        <option value="enforce">Enforce</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
