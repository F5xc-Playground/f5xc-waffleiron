import { useState, useEffect, useCallback } from 'react';
import { useConversion } from '../context/ConversionContext';
import { getXCStatus, pushToXC } from '../api';
import type { TranslationOutputs, PushResult, XCStatus } from '../types';

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Check,
  CheckCircle,
  X,
  AlertCircle,
  Loader2,
  Upload,
  AlertTriangle,
} from 'lucide-react';

const PUSHABLE_TYPES: { key: keyof TranslationOutputs; label: string }[] = [
  { key: 'app_firewall', label: 'App Firewall' },
  { key: 'exclusion_policy', label: 'WAF Exclusion Policy' },
  { key: 'service_policy', label: 'Service Policy' },
];

function getAvailableObjects(outputs: TranslationOutputs | null) {
  if (!outputs) return [];
  return PUSHABLE_TYPES.filter((t) => outputs[t.key] !== undefined);
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
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-2xl" showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Push to XC Tenant</DialogTitle>
          <DialogDescription className="sr-only">
            Push converted policy objects to your F5 XC tenant.
          </DialogDescription>
        </DialogHeader>

        {/* Body */}
        <div className="space-y-5">
          {/* Auth Section */}
          {loadingStatus ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Checking XC connection...
            </div>
          ) : isContainerConfigured ? (
            <Alert>
              <CheckCircle className="size-4 text-green-600 dark:text-green-400" />
              <AlertTitle className="text-green-800 dark:text-green-300">
                XC Connected
              </AlertTitle>
              {xcStatus?.tenant_url && (
                <AlertDescription className="text-green-600 dark:text-green-400">
                  {xcStatus.tenant_url}
                </AlertDescription>
              )}
            </Alert>
          ) : (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-foreground">
                XC Connection
              </h3>
              <div className="space-y-1.5">
                <Label htmlFor="modal-tenant-url">
                  Tenant URL
                </Label>
                <Input
                  id="modal-tenant-url"
                  type="text"
                  value={tenantUrl}
                  onChange={(e) => setTenantUrl(e.target.value)}
                  placeholder="https://your-tenant.console.ves.volterra.io"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="modal-api-token">
                  API Token
                </Label>
                <Input
                  id="modal-api-token"
                  type="password"
                  value={apiToken}
                  onChange={(e) => setApiToken(e.target.value)}
                  placeholder="Your XC API token"
                />
              </div>
              <div className="flex items-center gap-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleTestConnection}
                  disabled={testing || (!tenantUrl && !apiToken)}
                >
                  {testing ? (
                    <>
                      <Loader2 className="size-4 animate-spin" />
                      Testing...
                    </>
                  ) : (
                    'Test Connection'
                  )}
                </Button>
                {testResult === 'success' && (
                  <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                    <Check className="size-4" />
                    Connected
                  </span>
                )}
                {testResult === 'error' && (
                  <span className="flex items-center gap-1 text-sm text-destructive">
                    <AlertCircle className="size-4" />
                    {testError}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Object Checklist with Namespaces */}
          <div>
            <h3 className="mb-2 text-sm font-semibold text-foreground">
              Objects to Push
            </h3>
            {availableObjects.length === 0 ? (
              <p className="text-sm text-muted-foreground">
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
                        className="size-4 rounded border-input text-primary focus:ring-ring"
                      />
                      <span className="text-sm text-foreground">
                        {obj.label}
                      </span>
                      <Badge variant="secondary">
                        {ns}
                      </Badge>
                    </label>
                  );
                })}
              </div>
            )}
          </div>

          {/* HTTP LB Patch note */}
          {state.outputs?.http_lb_patch && (
            <Alert>
              <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" />
              <AlertTitle className="text-amber-800 dark:text-amber-300">
                HTTP LB Patch
              </AlertTitle>
              <AlertDescription className="text-amber-700 dark:text-amber-400">
                This policy includes CSRF and/or Data Guard settings that must be applied manually to your HTTP Load Balancer. These are included in the JSON download but cannot be pushed as standalone objects. See the gap report for details.
              </AlertDescription>
            </Alert>
          )}

          {/* Push Error */}
          {pushError && (
            <Alert variant="destructive">
              <AlertCircle className="size-4" />
              <AlertDescription>{pushError}</AlertDescription>
            </Alert>
          )}

          {/* Results */}
          {results && (
            <div className="rounded-lg border bg-muted/50 p-4">
              <h3 className="mb-2 text-sm font-semibold text-foreground">
                Push Results
              </h3>
              <div className="space-y-2">
                {results.map((r) => {
                  const label =
                    PUSHABLE_TYPES.find((t) => t.key === r.object_type)?.label ??
                    r.object_type;

                  return (
                    <div key={r.object_type} className="flex items-start gap-2 text-sm">
                      {r.success ? (
                        <Check className="mt-0.5 size-4 shrink-0 text-green-600 dark:text-green-400" strokeWidth={2.5} />
                      ) : (
                        <X className="mt-0.5 size-4 shrink-0 text-destructive" strokeWidth={2.5} />
                      )}
                      <div>
                        <span className={r.success ? 'font-medium text-green-800 dark:text-green-300' : 'font-medium text-destructive'}>
                          {label}
                        </span>
                        {r.namespace && (
                          <span className="ml-2 text-xs text-muted-foreground">
                            &rarr; {r.namespace}
                          </span>
                        )}
                        {r.error && (
                          <p className="mt-0.5 text-xs text-destructive">{r.error}</p>
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
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={onClose}
          >
            {results ? 'Close' : 'Cancel'}
          </Button>
          {!results && (
            <Button
              type="button"
              onClick={handlePush}
              disabled={pushing || selectedObjects.size === 0}
            >
              {pushing ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Pushing...
                </>
              ) : (
                <>
                  <Upload className="size-4" />
                  Push to XC
                </>
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
