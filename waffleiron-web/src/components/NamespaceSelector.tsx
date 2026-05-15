import { useState, useEffect } from 'react';
import { listNamespaces } from '../api';

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
        <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
          Namespace
        </label>
        <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
          <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading namespaces...
        </div>
      </div>
    );
  }

  if (fetchFailed) {
    return (
      <div>
        <label htmlFor="ns-input" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
          Namespace
        </label>
        <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">
          Could not load namespaces. Type a namespace manually.
        </p>
        <input
          id="ns-input"
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="e.g. shared"
          className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:focus:border-indigo-400 dark:focus:ring-indigo-400"
        />
      </div>
    );
  }

  return (
    <div>
      <label htmlFor="ns-select" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
        Namespace
      </label>
      <select
        id="ns-select"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:focus:border-indigo-400 dark:focus:ring-indigo-400"
      >
        {namespaces?.map((ns) => (
          <option key={ns} value={ns}>
            {ns}
          </option>
        ))}
      </select>
    </div>
  );
}
