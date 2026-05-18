import { useState, useCallback, useEffect } from 'react';
import type { AlarmOnlySignature, AlarmOnlyViolation, DecisionRequest } from '../types';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';

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

  const [bulkSigKey, setBulkSigKey] = useState(0);
  const [bulkViolKey, setBulkViolKey] = useState(0);

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

  return (
    <div className="space-y-6">
      {/* Signatures section */}
      {sigRows.length > 0 && (
        <Card>
          <div className="flex items-center justify-between px-6 py-4">
            <span className="text-sm font-semibold">
              Signatures
              <Badge variant="secondary" className="ml-2">
                {sigRows.length} alarm-only
              </Badge>
            </span>
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">Set all:</span>
              <Select
                key={bulkSigKey}
                onValueChange={(val) => {
                  bulkSetSigs(val as SignatureAction);
                  setBulkSigKey((k) => k + 1);
                }}
              >
                <SelectTrigger size="sm" className="w-[110px]">
                  <SelectValue placeholder="Select..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="exclude">Exclude</SelectItem>
                  <SelectItem value="enforce">Enforce</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs uppercase tracking-wider">ID</TableHead>
                  <TableHead className="text-xs uppercase tracking-wider">Scope</TableHead>
                  <TableHead className="w-32 text-xs uppercase tracking-wider">Decision</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sigRows.map((row) => (
                  <TableRow key={`${row.sig_id}-${row.scope}`}>
                    <TableCell className="font-mono text-foreground">
                      {row.sig_id}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{row.scope}</code>
                    </TableCell>
                    <TableCell>
                      <Select
                        value={row.action}
                        onValueChange={(val) => updateSig(row.sig_id, val as SignatureAction)}
                      >
                        <SelectTrigger size="sm" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="exclude">Exclude</SelectItem>
                          <SelectItem value="enforce">Enforce</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Violations section */}
      {violRows.length > 0 && (
        <Card>
          <div className="flex items-center justify-between px-6 py-4">
            <span className="text-sm font-semibold">
              Violations
              <Badge variant="secondary" className="ml-2">
                {violRows.length} alarm-only
              </Badge>
            </span>
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">Set all:</span>
              <Select
                key={bulkViolKey}
                onValueChange={(val) => {
                  bulkSetViols(val as ViolationAction);
                  setBulkViolKey((k) => k + 1);
                }}
              >
                <SelectTrigger size="sm" className="w-[110px]">
                  <SelectValue placeholder="Select..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="disable">Disable</SelectItem>
                  <SelectItem value="enforce">Enforce</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs uppercase tracking-wider">Violation</TableHead>
                  <TableHead className="w-32 text-xs uppercase tracking-wider">Decision</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {violRows.map((row) => (
                  <TableRow key={row.violation_name}>
                    <TableCell className="font-mono text-foreground">
                      {row.violation_name}
                    </TableCell>
                    <TableCell>
                      <Select
                        value={row.action}
                        onValueChange={(val) => updateViol(row.violation_name, val as ViolationAction)}
                      >
                        <SelectTrigger size="sm" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="disable">Disable</SelectItem>
                          <SelectItem value="enforce">Enforce</SelectItem>
                        </SelectContent>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
