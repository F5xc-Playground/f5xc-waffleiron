import { useState, useCallback, useEffect, useRef } from 'react';
import JSZip from 'jszip';
import { Loader2, Download, Check, Cloud, CheckCircle } from 'lucide-react';
import { useConversion } from '../context/ConversionContext';
import { getReport, getXCStatus, listNamespaces, runTranslation } from '../api';
import JsonViewer from '../components/JsonViewer';
import GapReport from '../components/GapReport';
import PushModal from '../components/PushModal';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import type { TranslationOutputs } from '../types';

const OBJECT_TYPES = [
  { key: 'app-firewall', label: 'App Firewall' },
  { key: 'waf-exclusion-policy', label: 'WAF Exclusion Policy' },
  { key: 'service-policy', label: 'Service Policy' },
  { key: '_advisory:http_lb_patch', label: 'HTTP LB Patch' },
] as const;

type OutputKey = (typeof OBJECT_TYPES)[number]['key'];

const NAMESPACE_OBJECTS = [
  { key: 'app-firewall', label: 'App Firewall' },
  { key: 'waf-exclusion-policy', label: 'WAF Exclusion Policy' },
  { key: 'service-policy', label: 'Service Policy' },
] as const;

function getAvailableTabs(outputs: TranslationOutputs) {
  return OBJECT_TYPES.filter(
    (t) => outputs[t.key as keyof TranslationOutputs] !== undefined,
  );
}

export default function ReviewView() {
  const { state, dispatch } = useConversion();
  const [activeTab, setActiveTab] = useState<OutputKey | null>(null);
  const [zipping, setZipping] = useState(false);
  const [translating, setTranslating] = useState(false);
  const [translateError, setTranslateError] = useState<string | null>(null);
  const [showPushModal, setShowPushModal] = useState(false);
  const initializedRef = useRef(false);

  const defaultName = state.analysis?.policy_info.name ?? '';
  const [policyName, setPolicyName] = useState(defaultName);
  const [namespace, setNamespace] = useState('shared');
  const [advancedNs, setAdvancedNs] = useState(false);
  const [perObjectNs, setPerObjectNs] = useState<Record<string, string>>({
    'app-firewall': 'shared',
    'waf-exclusion-policy': 'shared',
    'service-policy': 'shared',
  });

  // Namespace loading from XC tenant
  const [xcNamespaces, setXcNamespaces] = useState<string[] | null>(null);
  const [nsLoading, setNsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await getXCStatus();
        if (cancelled) return;
        dispatch({ type: 'XC_STATUS_LOADED', status });
        if (status.configured) {
          const ns = await listNamespaces();
          if (cancelled) return;
          const withShared = ns.includes('shared') ? ns : ['shared', ...ns];
          setXcNamespaces(withShared);
        }
      } catch {
        // Fall back to text inputs
      } finally {
        if (!cancelled) setNsLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [dispatch]);

  useEffect(() => {
    if (defaultName && !policyName) setPolicyName(defaultName);
  }, [defaultName]);

  const outputs = state.outputs;
  const sessionId = state.sessionId;

  const tabs = outputs ? getAvailableTabs(outputs) : [];

  useEffect(() => {
    if (!initializedRef.current && tabs.length > 0) {
      setActiveTab(tabs[0].key);
      initializedRef.current = true;
    }
  }, [tabs]);

  const handleObjectSave = useCallback((objectType: string, updated: object) => {
    if (!outputs) return;
    const newOutputs = { ...outputs, [objectType]: updated };
    dispatch({ type: 'OUTPUT_EDITED', outputs: newOutputs });
  }, [outputs, dispatch]);

  const handleTranslate = useCallback(async () => {
    if (!sessionId) return;

    setTranslateError(null);
    setTranslating(true);

    try {
      // Backend expects underscore keys for namespaces dict; remap from kebab-case UI keys.
      const nsArg = advancedNs
        ? {
            app_firewall: perObjectNs['app-firewall'] ?? namespace,
            exclusion_policy: perObjectNs['waf-exclusion-policy'] ?? namespace,
            service_policy: perObjectNs['service-policy'] ?? namespace,
          }
        : namespace;
      const result = await runTranslation(sessionId, nsArg, policyName || undefined, state.overrides);
      dispatch({ type: 'TRANSLATION_COMPLETE', outputs: result });
    } catch (err) {
      setTranslateError(err instanceof Error ? err.message : 'Translation failed.');
    } finally {
      setTranslating(false);
    }
  }, [sessionId, namespace, advancedNs, perObjectNs, policyName, state.overrides, dispatch]);

  const handleDownloadZip = useCallback(async () => {
    if (!outputs || !sessionId) return;

    setZipping(true);
    try {
      const zip = new JSZip();

      for (const t of OBJECT_TYPES) {
        const data = outputs[t.key as keyof TranslationOutputs];
        if (data) {
          zip.file(`${t.key}.json`, JSON.stringify(data, null, 2));
        }
      }

      try {
        const markdown = await getReport(sessionId, 'markdown');
        zip.file('gap_report.md', markdown);
      } catch {
        // Gap report is optional
      }

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waffleiron-${policyName || sessionId}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to create ZIP:', err);
    } finally {
      setZipping(false);
    }
  }, [outputs, sessionId, policyName]);

  if (!sessionId) {
    return (
      <div className="flex-1 px-6 py-4">
        <div className="mx-auto max-w-4xl rounded-lg border border-dashed border-border p-12 text-center">
          <p className="text-muted-foreground">
            No conversion session available.
          </p>
        </div>
      </div>
    );
  }

  const hasPushResults = state.pushResults && state.pushResults.length > 0;
  const allPushSucceeded = state.pushResults?.every((r) => r.success);

  return (
    <div className="flex-1 px-6 py-4">
      <div className="mx-auto max-w-5xl space-y-6">
        {/* Output Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Output Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="policyName">Base Name</Label>
                <Input
                  id="policyName"
                  value={policyName}
                  onChange={(e) => setPolicyName(e.target.value)}
                  placeholder="e.g. my-policy"
                />
                <p className="text-xs text-muted-foreground">
                  Base for XC object names (auto-sanitized)
                </p>
              </div>
              {!advancedNs && (
                <div className="space-y-1.5">
                  <Label htmlFor="namespace">Namespace</Label>
                  {nsLoading ? (
                    <div className="flex h-9 items-center gap-2 rounded-md border border-input bg-transparent px-3 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Loading namespaces...
                    </div>
                  ) : xcNamespaces ? (
                    <Select value={namespace} onValueChange={setNamespace}>
                      <SelectTrigger id="namespace" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {xcNamespaces.map((ns) => (
                          <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Input
                      id="namespace"
                      value={namespace}
                      onChange={(e) => setNamespace(e.target.value)}
                      placeholder="e.g. my-namespace"
                    />
                  )}
                </div>
              )}
            </div>

            {/* Per-object namespace toggle */}
            <div className="flex items-center gap-2">
              <Switch
                id="advancedNs"
                checked={advancedNs}
                onCheckedChange={(checked) => {
                  setAdvancedNs(checked);
                  if (checked) {
                    setPerObjectNs({
                      'app-firewall': namespace,
                      'waf-exclusion-policy': namespace,
                      'service-policy': namespace,
                    });
                  }
                }}
              />
              <Label htmlFor="advancedNs">Per-object namespaces</Label>
            </div>

            {advancedNs && (
              <div className="rounded-md border border-border bg-muted/50 p-3">
                <div className="space-y-2">
                  {NAMESPACE_OBJECTS.map((obj) => (
                    <div key={obj.key} className="flex items-center gap-3">
                      <span className="w-40 shrink-0 text-sm text-muted-foreground">
                        {obj.label}
                      </span>
                      {xcNamespaces ? (
                        <Select
                          value={perObjectNs[obj.key] ?? namespace}
                          onValueChange={(value) =>
                            setPerObjectNs((prev) => ({ ...prev, [obj.key]: value }))
                          }
                        >
                          <SelectTrigger className="w-full">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {xcNamespaces.map((ns) => (
                              <SelectItem key={ns} value={ns}>{ns}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <Input
                          value={perObjectNs[obj.key] ?? namespace}
                          onChange={(e) =>
                            setPerObjectNs((prev) => ({ ...prev, [obj.key]: e.target.value }))
                          }
                          placeholder="namespace"
                        />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {translateError && (
              <Alert variant="destructive">
                <AlertDescription>{translateError}</AlertDescription>
              </Alert>
            )}

            <div className="flex items-center gap-3">
              <Button
                onClick={handleTranslate}
                disabled={translating || !policyName.trim() || (!advancedNs && !namespace.trim())}
              >
                {translating ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : outputs ? (
                  'Regenerate Output'
                ) : (
                  'Generate Output'
                )}
              </Button>
              {outputs && !translating && (
                <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                  <Check className="h-4 w-4" />
                  Output ready
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Export Actions — only show when outputs exist */}
        {outputs && (
          <>
            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={handleDownloadZip}
                disabled={zipping}
                className="flex flex-col items-center gap-2 rounded-lg border border-border bg-card px-5 py-5 text-center shadow-sm transition-colors hover:border-primary/30 hover:bg-primary/5"
              >
                {zipping ? (
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                ) : (
                  <Download className="h-8 w-8 text-muted-foreground" />
                )}
                <span className="text-sm font-semibold text-card-foreground">
                  {zipping ? 'Creating ZIP...' : 'Download JSON'}
                </span>
                <span className="text-xs text-muted-foreground">
                  Export all objects as a ZIP archive
                </span>
              </button>

              <button
                type="button"
                onClick={() => setShowPushModal(true)}
                className="flex flex-col items-center gap-2 rounded-lg border border-border bg-card px-5 py-5 text-center shadow-sm transition-colors hover:border-primary/30 hover:bg-primary/5"
              >
                {hasPushResults && allPushSucceeded ? (
                  <CheckCircle className="h-8 w-8 text-green-500 dark:text-green-400" />
                ) : (
                  <Cloud className="h-8 w-8 text-primary" />
                )}
                <span className="text-sm font-semibold text-card-foreground">
                  {hasPushResults && allPushSucceeded ? 'Pushed to XC' : 'Push to XC Tenant'}
                </span>
                <span className="text-xs text-muted-foreground">
                  {hasPushResults && allPushSucceeded
                    ? 'Objects deployed — click to push again'
                    : 'Deploy objects directly to your tenant'}
                </span>
              </button>
            </div>

            {/* Tabbed JSON Panels */}
            {tabs.length > 0 && activeTab && (
              <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as OutputKey)}>
                <TabsList>
                  {tabs.map((tab) => (
                    <TabsTrigger key={tab.key} value={tab.key}>
                      {tab.label}
                    </TabsTrigger>
                  ))}
                </TabsList>

                {tabs.map((tab) => (
                  <TabsContent key={tab.key} value={tab.key}>
                    {tab.key === '_advisory:http_lb_patch' && (
                      <div className="mb-3 rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 dark:border-yellow-700/40 dark:bg-yellow-900/20">
                        <p className="text-sm text-foreground">
                          <span className="font-semibold">Not pushed to XC.</span> CSRF and Data Guard are configured at the HTTP Load Balancer level in XC, not on the WAF policy. Apply these settings manually to your HTTP LB after deployment. This snippet is included in the JSON download for reference.
                        </p>
                      </div>
                    )}
                    {outputs[tab.key as keyof TranslationOutputs] && (
                      <JsonViewer
                        data={outputs[tab.key as keyof TranslationOutputs]!}
                        title={tab.label}
                        objectType={tab.key}
                        onSave={(updated) => handleObjectSave(tab.key, updated)}
                      />
                    )}
                  </TabsContent>
                ))}
              </Tabs>
            )}

            {/* Gap Report */}
            <GapReport sessionId={sessionId} />
          </>
        )}
      </div>

      {/* Push Modal */}
      {showPushModal && <PushModal onClose={() => setShowPushModal(false)} />}
    </div>
  );
}
