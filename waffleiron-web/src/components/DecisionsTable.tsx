import { useState, useCallback, useEffect, useMemo } from 'react';
import {
  type ColumnDef,
  type SortingState,
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import type { AlarmOnlySignature, AlarmOnlyViolation, DecisionRequest } from '../types';
import { Card, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';

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

function DataTablePagination<T>({ table }: { table: ReturnType<typeof useReactTable<T>> }) {
  return (
    <div className="flex items-center justify-between px-2 py-2">
      <span className="text-xs text-muted-foreground">
        {table.getRowCount()} row{table.getRowCount() !== 1 ? 's' : ''}
      </span>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="icon"
          className="h-7 w-7"
          onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>
        <span className="px-2 text-xs text-muted-foreground">
          {table.getState().pagination.pageIndex + 1} / {table.getPageCount()}
        </span>
        <Button
          variant="outline"
          size="icon"
          className="h-7 w-7"
          onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
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
  const [sigSorting, setSigSorting] = useState<SortingState>([]);
  const [violSorting, setViolSorting] = useState<SortingState>([]);

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

  const sigColumns = useMemo<ColumnDef<SigRow>[]>(() => [
    {
      accessorKey: 'sig_id',
      header: ({ column }) => (
        <Button variant="ghost" size="sm" className="-ml-3 h-8" onClick={() => column.toggleSorting()}>
          ID
          <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => row.getValue('sig_id'),
    },
    {
      accessorKey: 'scope',
      header: ({ column }) => (
        <Button variant="ghost" size="sm" className="-ml-3 h-8" onClick={() => column.toggleSorting()}>
          Scope
          <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => row.getValue('scope'),
    },
    {
      accessorKey: 'action',
      header: 'Decision',
      cell: ({ row }) => (
        <Select
          value={row.original.action}
          onValueChange={(val) => updateSig(row.original.sig_id, val as SignatureAction)}
        >
          <SelectTrigger size="sm" className="w-[110px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="exclude">Exclude</SelectItem>
            <SelectItem value="enforce">Enforce</SelectItem>
          </SelectContent>
        </Select>
      ),
      enableSorting: false,
    },
  ], [updateSig]);

  const violColumns = useMemo<ColumnDef<ViolRow>[]>(() => [
    {
      accessorKey: 'violation_name',
      header: ({ column }) => (
        <Button variant="ghost" size="sm" className="-ml-3 h-8" onClick={() => column.toggleSorting()}>
          Violation
          <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => row.getValue('violation_name'),
    },
    {
      accessorKey: 'action',
      header: 'Decision',
      cell: ({ row }) => (
        <Select
          value={row.original.action}
          onValueChange={(val) => updateViol(row.original.violation_name, val as ViolationAction)}
        >
          <SelectTrigger size="sm" className="w-[110px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="disable">Disable</SelectItem>
            <SelectItem value="enforce">Enforce</SelectItem>
          </SelectContent>
        </Select>
      ),
      enableSorting: false,
    },
  ], [updateViol]);

  const sigTable = useReactTable({
    data: sigRows,
    columns: sigColumns,
    state: { sorting: sigSorting },
    onSortingChange: setSigSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 10 } },
  });

  const violTable = useReactTable({
    data: violRows,
    columns: violColumns,
    state: { sorting: violSorting },
    onSortingChange: setViolSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 10 } },
  });

  return (
    <div className="space-y-6">
      {sigRows.length > 0 && (
        <Card>
          <div className="flex items-center justify-between px-6">
            <span className="text-base font-semibold">Signatures</span>
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
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  {sigTable.getHeaderGroups().map((headerGroup) => (
                    <TableRow key={headerGroup.id} className="bg-muted dark:bg-white/10">
                      {headerGroup.headers.map((header) => (
                        <TableHead key={header.id} className="text-xs uppercase tracking-wider">
                          {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                        </TableHead>
                      ))}
                    </TableRow>
                  ))}
                </TableHeader>
                <TableBody>
                  {sigTable.getRowModel().rows.length ? (
                    sigTable.getRowModel().rows.map((row) => (
                      <TableRow key={row.id}>
                        {row.getVisibleCells().map((cell) => (
                          <TableCell key={cell.id}>
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={sigColumns.length} className="h-16 text-center text-muted-foreground">
                        No results.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
            {sigTable.getPageCount() > 1 && <DataTablePagination table={sigTable} />}
          </CardContent>
        </Card>
      )}

      {violRows.length > 0 && (
        <Card>
          <div className="flex items-center justify-between px-6">
            <span className="text-base font-semibold">Violations</span>
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
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  {violTable.getHeaderGroups().map((headerGroup) => (
                    <TableRow key={headerGroup.id} className="bg-muted dark:bg-white/10">
                      {headerGroup.headers.map((header) => (
                        <TableHead key={header.id} className="text-xs uppercase tracking-wider">
                          {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                        </TableHead>
                      ))}
                    </TableRow>
                  ))}
                </TableHeader>
                <TableBody>
                  {violTable.getRowModel().rows.length ? (
                    violTable.getRowModel().rows.map((row) => (
                      <TableRow key={row.id}>
                        {row.getVisibleCells().map((cell) => (
                          <TableCell key={cell.id}>
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={violColumns.length} className="h-16 text-center text-muted-foreground">
                        No results.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
            {violTable.getPageCount() > 1 && <DataTablePagination table={violTable} />}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
