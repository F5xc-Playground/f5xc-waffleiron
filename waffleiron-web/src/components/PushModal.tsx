import { useState, useEffect, useCallback } from 'react';
import { useConversion } from '../context/ConversionContext';
import { getXCStatus, pushToXC } from '../api';
import type { TranslationOutputs, PushResult, XCStatus } from '../types';

const OBJECT_TYPES: { key: keyof TranslationOutputs; label: string }[] = [
  { key: 'app_firewall', label: 'App Firewall' },
  { key: 'exclusion_policy', label: 'WAF Exclusion Policy' },
  { key: 'service_policy', label: 'Service Policy' },
  { key: 'http_lb_patch', label: 'HTTP LB Patch' },
];

function getAvailableObjects(outputs: TranslationOutputs | null) {
  if (!outputs) return [];
  return OBJECT_TYPES.filter((t) => outputs[t.key] !== undefined);
}

function getObjectNamespace(outputs: TranslationOutputs, key: string): string {
  const obj = outputs[key as keyof TranslationOutputs] as Record<string, unknown> | undefined;
  const meta = obj?.metadata as Record<string, unknown> | undefined;
  return (meta?.namespace as string) ?? 'default';
}

interface PushModalProps {
  onClose: () => void;
}

export default function PushModal({ onClose }: PushModalProps) {
  const { state, dispatch } = useConversion();

  const [xcStatus, setXcStatus] = useState<XCStatus | null>(state.xcStatus);
  const [loadingStatus, setLoadingStatus] = useState(!state.xcStatus);

  const [tenantUrl, setTenantUrl] = useState('');
  const [apiToken, setApiToken] = useState('');
  const [testResult, setTestResult] = useState<'success' | 'error' | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);

  const availableObjects = getAvailableObjects(state.outputs);
  const [selectedObjects, setSelectedObjects] = useState<Set<string>>(
    () => new Set(availableObjects.map((o) => o.key)),
  );

  const [pushing, setPushing] = useState(false);
  const [pushError, setPushError] = useState<string | null>(null);
  const [results, setResults] = useState<PushResult[] | null>(state.pushResults);

  useEffect(() => {
    if (state.xcStatus) {
      setXcStatus(state.xcStatus);
      setLoadingStatus(false);
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const status = await getXCStatus();
        if (cancelled) return;
        setXcStatus(status);
        dispatch({ type: 'XC_STATUS_LOADED', status });
        if (status.tenant_url) {
          setTenantUrl(status.tenant_url);
        }
      } catch {
        // Non-critical — user can still enter creds manually
      } finally {
        if (!cancelled) setLoadingStatus(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [state.xcStatus, dispatch]);

  const isContainerConfigured = xcStatus?.configured === true;

  const handleTestConnection = useCallback(async () => {
    setTesting(true);
    setTestResult(null);
    setTestError(null);
    try {
      const status = await getXCStatus();
      if (status.configured || tenantUrl) {
        setTestResult('success');
      } else {
        setTestResult('error');
        setTestError('Connection could not be verified.');
      }
    } catch (err) {
      setTestResult('error');
      setTestError(err instanceof Error ? err.message : 'Connection test failed.');
    } finally {
      setTesting(false);
    }
  }, [tenantUrl]);

  const toggleObject = useCallback((key: string) => {
    setSelectedObjects((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }, []);

  const handlePush = useCallback(async () => {
    if (!state.sessionId || selectedObjects.size === 0) return;

    setPushing(true);
    setPushError(null);
    setResults(null);

    try {
      const pushResults = await pushToXC(
        state.sessionId,
        Array.from(selectedObjects),
        isContainerConfigured ? undefined : tenantUrl || undefined,
        isContainerConfigured ? undefined : apiToken || undefined,
      );
      setResults(pushResults);
      dispatch({ type: 'PUSH_COMPLETE', results: pushResults });
    } catch (err) {
      setPushError(err instanceof Error ? err.message : 'Push failed. Please try again.');
    } finally {
      setPushing(false);
    }
  }, [state.sessionId, tenantUrl, apiToken, selectedObjects, isContainerConfigured, dispatch]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/50 p-4 backdrop-blur-sm">
      <div className="relative w-full max-w-2xl rounded-xl border border-gray-200 bg-white shadow-2xl dark:border-gray-700 dark:bg-gray-900">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Push to XC Tenant
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-500 dark:hover:bg-gray-800 dark:hover:text-gray-300"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="space-y-5 px-6 py-5">
          {/* Auth Section */}
          {loadingStatus ? (
            <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
              <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Checking XC connection...
            </div>
          ) : isContainerConfigured ? (
            <div className="rounded-lg border border-green-200 bg-green-50 px-4 py-2.5 dark:border-green-800 dark:bg-green-900/20">
              <div className="flex items-center gap-2">
                <svg className="h-5 w-5 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-sm font-medium text-green-800 dark:text-green-300">
                  XC Connected
                </span>
                {xcStatus?.tenant_url && (
                  <span className="ml-2 text-xs text-green-600 dark:text-green-400">
                    ({xcStatus.tenant_url})
                  </span>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                XC Connection
              </h3>
              <div>
                <label htmlFor="modal-tenant-url" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Tenant URL
                </label>
                <input
                  id="modal-tenant-url"
                  type="text"
                  value={tenantUrl}
                  onChange={(e) => setTenantUrl(e.target.value)}
                  placeholder="https://your-tenant.console.ves.volterra.io"
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-indigo-400 dark:focus:ring-indigo-400"
                />
              </div>
              <div>
                <label htmlFor="modal-api-token" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  API Token
                </label>
                <input
                  id="modal-api-token"
                  type="password"
                  value={apiToken}
                  onChange={(e) => setApiToken(e.target.value)}
                  placeholder="Your XC API token"
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-indigo-400 dark:focus:ring-indigo-400"
                />
              </div>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testing || (!tenantUrl && !apiToken)}
                  className="inline-flex items-center gap-2 rounded-md bg-gray-100 px-3 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-200 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
                >
                  {testing ? 'Testing...' : 'Test Connection'}
                </button>
                {testResult === 'success' && (
                  <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    Connected
                  </span>
                )}
                {testResult === 'error' && (
                  <span className="text-sm text-red-600 dark:text-red-400">
                    {testError}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Object Checklist with Namespaces */}
          <div>
            <h3 className="mb-2 text-sm font-semibold text-gray-900 dark:text-white">
              Objects to Push
            </h3>
            {availableObjects.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                No objects available.
              </p>
            ) : (
              <div className="space-y-2">
                {availableObjects.map((obj) => {
                  const ns = state.outputs
                    ? getObjectNamespace(state.outputs, obj.key)
                    : 'default';
                  return (
                    <label key={obj.key} className="flex items-center gap-3 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedObjects.has(obj.key)}
                        onChange={() => toggleObject(obj.key)}
                        className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-700"
                      />
                      <span className="text-sm text-gray-700 dark:text-gray-300">
                        {obj.label}
                      </span>
                      <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500 dark:bg-gray-700 dark:text-gray-400">
                        {ns}
                      </span>
                    </label>
                  );
                })}
              </div>
            )}
          </div>

          {/* Push Error */}
          {pushError && (
            <div className="rounded-md bg-red-50 px-4 py-3 dark:bg-red-900/20">
              <p className="text-sm text-red-700 dark:text-red-400">{pushError}</p>
            </div>
          )}

          {/* Results */}
          {results && (
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-800">
              <h3 className="mb-2 text-sm font-semibold text-gray-900 dark:text-white">
                Push Results
              </h3>
              <div className="space-y-2">
                {results.map((r) => {
                  const label =
                    OBJECT_TYPES.find((t) => t.key === r.object_type)?.label ??
                    r.object_type;

                  return (
                    <div key={r.object_type} className="flex items-start gap-2 text-sm">
                      {r.success ? (
                        <svg className="mt-0.5 h-4 w-4 shrink-0 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <svg className="mt-0.5 h-4 w-4 shrink-0 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      )}
                      <div>
                        <span className={r.success ? 'font-medium text-green-800 dark:text-green-300' : 'font-medium text-red-800 dark:text-red-300'}>
                          {label}
                        </span>
                        {r.namespace && (
                          <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                            → {r.namespace}
                          </span>
                        )}
                        {r.error && (
                          <p className="mt-0.5 text-xs text-red-600 dark:text-red-400">{r.error}</p>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 border-t border-gray-200 px-6 py-4 dark:border-gray-700">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
          >
            {results ? 'Close' : 'Cancel'}
          </button>
          {!results && (
            <button
              type="button"
              onClick={handlePush}
              disabled={pushing || selectedObjects.size === 0}
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {pushing ? (
                <>
                  <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Pushing...
                </>
              ) : (
                'Push to XC'
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
