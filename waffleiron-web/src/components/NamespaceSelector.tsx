import { useState, useEffect } from 'react';
import { listNamespaces } from '../api';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2 } from 'lucide-react';

interface NamespaceSelectorProps {
  value: string;
  onChange: (namespace: string) => void;
  tenantUrl?: string;
  apiToken?: string;
}

export default function NamespaceSelector({
  value,
  onChange,
  tenantUrl,
  apiToken,
}: NamespaceSelectorProps) {
  const [namespaces, setNamespaces] = useState<string[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [fetchFailed, setFetchFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function fetch() {
      setLoading(true);
      setFetchFailed(false);
      try {
        const result = await listNamespaces(tenantUrl, apiToken);
        if (cancelled) return;
        // Ensure "shared" is always present
        const withShared = result.includes('shared')
          ? result
          : ['shared', ...result];
        setNamespaces(withShared);
        // If no value selected yet, default to "shared"
        if (!value && withShared.length > 0) {
          onChange('shared');
        }
      } catch {
        if (cancelled) return;
        setFetchFailed(true);
        setNamespaces(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetch();
    return () => {
      cancelled = true;
    };
    // Re-fetch when credentials change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantUrl, apiToken]);

  if (loading) {
    return (
      <div className="flex items-center gap-2">
        <Label>Namespace</Label>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" />
          Loading namespaces...
        </div>
      </div>
    );
  }

  if (fetchFailed) {
    return (
      <div className="space-y-1.5">
        <Label htmlFor="ns-input">Namespace</Label>
        <p className="text-xs text-amber-600 dark:text-amber-400">
          Could not load namespaces. Type a namespace manually.
        </p>
        <Input
          id="ns-input"
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="e.g. shared"
        />
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      <Label htmlFor="ns-select">Namespace</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id="ns-select" className="w-full">
          <SelectValue placeholder="Select namespace" />
        </SelectTrigger>
        <SelectContent>
          {namespaces?.map((ns) => (
            <SelectItem key={ns} value={ns}>
              {ns}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
