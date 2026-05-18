import type { ConversionSummary, PolicyInfo, PolicyOverrides, BotGap, BlockingPageGap, IpIntelGap, UntranslatableSummary, LimitWarning } from '../types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { AlertTriangle, ShieldAlert } from 'lucide-react';

interface SummaryCardsProps {
  summary: ConversionSummary;
  policyInfo: PolicyInfo;
  overrides: PolicyOverrides;
  onOverridesChange: (overrides: PolicyOverrides) => void;
  botGaps: BotGap[];
  blockingPageGaps: BlockingPageGap[];
  ipIntelGaps: IpIntelGap[];
  untranslatable: UntranslatableSummary;
  warnings: LimitWarning[];
}

type TranslationStatus = 'full' | 'partial' | 'none';

const PROTECTIONS: { key: string; label: string; base: TranslationStatus }[] = [
  { key: 'blocking_page', label: 'Custom Blocking Page', base: 'full' },
  { key: 'bot_defense', label: 'Bot Defense', base: 'full' },
  { key: 'geolocation', label: 'Geolocation', base: 'full' },
  { key: 'ip_intelligence', label: 'IP Intelligence', base: 'full' },
  { key: 'data_guard', label: 'Data Guard', base: 'full' },
  { key: 'csrf', label: 'CSRF Protection', base: 'full' },
  { key: 'brute_force', label: 'Brute Force', base: 'none' },
  { key: 'session_tracking', label: 'Session Tracking', base: 'none' },
];

function classifyProtections(
  features: Record<string, boolean>,
  botGaps: BotGap[],
  blockingPageGaps: BlockingPageGap[],
  ipIntelGaps: IpIntelGap[],
) {
  const full: string[] = [];
  const partial: { label: string; key: string }[] = [];
  const none: string[] = [];

  for (const p of PROTECTIONS) {
    if (!features[p.key]) continue;

    let status = p.base;
    if (p.key === 'bot_defense' && botGaps.length > 0) status = 'partial';
    else if (p.key === 'blocking_page' && blockingPageGaps.length > 0) status = 'partial';
    else if (p.key === 'ip_intelligence' && ipIntelGaps.length > 0) status = 'partial';

    if (status === 'full') full.push(p.label);
    else if (status === 'partial') partial.push({ label: p.label, key: p.key });
    else none.push(p.label);
  }

  return { full, partial, none };
}

export default function SummaryCards({ summary, policyInfo, overrides, onOverridesChange, botGaps, blockingPageGaps, ipIntelGaps, untranslatable, warnings }: SummaryCardsProps) {
  const prot = classifyProtections(policyInfo.features, botGaps, blockingPageGaps, ipIntelGaps);
  const translated = summary.directly_translated + summary.decisions_required;
  const pct = summary.total > 0 ? Math.round((translated / summary.total) * 100) : 0;

  const enabledSigSets = (policyInfo.signature_sets ?? [])
    .filter((s) => s.enabled)
    .map((s) => s.name.replace(' Signatures', ''));

  const effectiveMode = overrides.enforcement_mode ?? policyInfo.enforcement_mode;
  const effectiveAccuracy = overrides.signature_accuracy ?? policyInfo.signature_accuracy;
  const effectiveStaging = overrides.staging_enabled ?? policyInfo.staging_enabled;
  const effectiveThreatCampaigns = overrides.threat_campaigns_enabled ?? policyInfo.threat_campaigns_enabled;

  const setOverride = (key: keyof PolicyOverrides, value: unknown) => {
    const next = { ...overrides, [key]: value };
    // Remove override if it matches the source value
    if (key === 'enforcement_mode' && value === policyInfo.enforcement_mode) delete next.enforcement_mode;
    if (key === 'signature_accuracy' && value === policyInfo.signature_accuracy) delete next.signature_accuracy;
    if (key === 'staging_enabled' && value === policyInfo.staging_enabled) delete next.staging_enabled;
    if (key === 'threat_campaigns_enabled' && value === policyInfo.threat_campaigns_enabled) delete next.threat_campaigns_enabled;
    onOverridesChange(next);
  };

  const hasOverrides = Object.keys(overrides).length > 0;

  return (
    <div className="space-y-4">
      {/* 1. Hero */}
      <Card>
        <CardContent className="flex items-center justify-center gap-3 py-4">
          <span className="text-4xl font-bold text-primary">{pct}%</span>
          <span className="text-sm text-muted-foreground">
            translation coverage ({translated}/{summary.total} items)
          </span>
        </CardContent>
      </Card>

      {/* 2. Policy Overview (merged Source + Translated) */}
      <Card>
        <CardHeader className="pb-0">
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle className="text-lg">Policy Overview</CardTitle>
              <CardDescription className="mt-1">
                Source: <span className="font-medium text-foreground">{policyInfo.name}</span>
                <span className="mx-2 text-border">|</span>
                Encoding: <span className="font-medium text-foreground">{policyInfo.encoding}</span>
              </CardDescription>
            </div>
            {hasOverrides && (
              <Badge variant="secondary">Modified</Badge>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Editable Detection Settings */}
          <div>
            <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Detection Settings</h3>
            <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-4 text-sm sm:grid-cols-4">
              <div>
                <label className="block text-muted-foreground">Enforcement</label>
                <Select
                  value={effectiveMode}
                  onValueChange={(val) => setOverride('enforcement_mode', val)}
                >
                  <SelectTrigger className="mt-1.5 w-full" size="sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="blocking">Blocking</SelectItem>
                    <SelectItem value="transparent">Transparent</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="block text-muted-foreground">Accuracy</label>
                <Select
                  value={effectiveAccuracy}
                  onValueChange={(val) => setOverride('signature_accuracy', val)}
                >
                  <SelectTrigger className="mt-1.5 w-full" size="sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="high_medium">High + Medium</SelectItem>
                    <SelectItem value="all">All</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="block text-muted-foreground">Staging</label>
                <Select
                  value={effectiveStaging ? 'true' : 'false'}
                  onValueChange={(val) => setOverride('staging_enabled', val === 'true')}
                >
                  <SelectTrigger className="mt-1.5 w-full" size="sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="true">Enabled</SelectItem>
                    <SelectItem value="false">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="block text-muted-foreground">Threat Campaigns</label>
                <Select
                  value={effectiveThreatCampaigns ? 'true' : 'false'}
                  onValueChange={(val) => setOverride('threat_campaigns_enabled', val === 'true')}
                >
                  <SelectTrigger className="mt-1.5 w-full" size="sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="true">Enabled</SelectItem>
                    <SelectItem value="false">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* Protections */}
          {prot.full.length > 0 && (
            <div>
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Protections</h3>
              <div className="mt-1.5 flex flex-wrap gap-2">
                {prot.full.map((label) => (
                  <Badge key={label} variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    {label}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Attack Types */}
          {enabledSigSets.length > 0 && (
            <div>
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Attack Types ({enabledSigSets.length})
              </h3>
              <div className="mt-1.5 flex flex-wrap gap-2">
                {enabledSigSets.map((name) => (
                  <Badge key={name} variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    {name}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Service Policy Rules */}
          {((policyInfo.entity_counts.whitelist_ips ?? 0) > 0 || policyInfo.features.geolocation || policyInfo.features.ip_intelligence) && (
            <div>
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Service Policy Rules</h3>
              <div className="mt-1.5 flex flex-wrap gap-2">
                {(policyInfo.entity_counts.whitelist_ips ?? 0) > 0 && (
                  <Badge variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    {policyInfo.entity_counts.whitelist_ips} IP allow rule{policyInfo.entity_counts.whitelist_ips !== 1 ? 's' : ''}
                  </Badge>
                )}
                {policyInfo.features.geolocation && (
                  <Badge variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    Geolocation deny rules
                  </Badge>
                )}
                {policyInfo.features.ip_intelligence && (
                  <Badge variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    IP intelligence deny rules
                  </Badge>
                )}
              </div>
            </div>
          )}

          {/* Exclusion & Violation Rules */}
          {((policyInfo.entity_counts.signature_overrides ?? 0) > 0 || (policyInfo.entity_counts.violations ?? 0) > 0) && (
            <div>
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Rules</h3>
              <div className="mt-1.5 flex flex-wrap gap-2">
                {(policyInfo.entity_counts.signature_overrides ?? 0) > 0 && (
                  <Badge variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    {policyInfo.entity_counts.signature_overrides} global signature exclusion{policyInfo.entity_counts.signature_overrides !== 1 ? 's' : ''}
                  </Badge>
                )}
                {(policyInfo.entity_counts.violations ?? 0) > 0 && (
                  <Badge variant="secondary" className="bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300">
                    {policyInfo.entity_counts.violations} violation setting{policyInfo.entity_counts.violations !== 1 ? 's' : ''}
                  </Badge>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 3. Partial */}
      {prot.partial.length > 0 && (
        <Card>
          <CardHeader className="pb-0">
            <CardTitle className="flex items-center gap-2 text-lg">
              <AlertTriangle className="size-5 text-yellow-600 dark:text-yellow-400" />
              Partial
            </CardTitle>
          </CardHeader>

          <CardContent className="space-y-4">
            {prot.partial.map((p) => (
              <div key={p.key} className="rounded-md border border-yellow-200 bg-yellow-50/50 p-4 dark:border-yellow-800/30 dark:bg-yellow-900/10">
                <h3 className="text-sm font-semibold text-yellow-800 dark:text-yellow-300">{p.label}</h3>

                {p.key === 'bot_defense' && (
                  <>
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-400">
                      Bot categories are translated, but the following AWAF actions have no XC equivalent and will be omitted.
                    </p>
                    <Table className="mt-2 text-xs">
                      <TableHeader>
                        <TableRow className="border-yellow-200 dark:border-yellow-800/30">
                          <TableHead className="h-7 text-muted-foreground">Category</TableHead>
                          <TableHead className="h-7 text-muted-foreground">AWAF Action</TableHead>
                          <TableHead className="h-7 text-muted-foreground">Gap</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {botGaps.map((gap) => (
                          <TableRow key={gap.category} className="border-yellow-100 dark:border-yellow-800/20">
                            <TableCell className="py-1 font-medium">{gap.category}</TableCell>
                            <TableCell className="py-1">
                              <code className="rounded bg-yellow-100 px-1 py-0.5 dark:bg-yellow-900/30">{gap.asm_action}</code>
                            </TableCell>
                            <TableCell className="py-1 text-muted-foreground">{gap.reason}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </>
                )}

                {p.key === 'blocking_page' && (
                  <>
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-400">
                      XC only supports <code className="rounded bg-yellow-100 px-1 dark:bg-yellow-900/30">{'{{request_id}}'}</code> in custom blocking pages. The following AWAF variables will render as literal text.
                    </p>
                    <Table className="mt-2 text-xs">
                      <TableHeader>
                        <TableRow className="border-yellow-200 dark:border-yellow-800/30">
                          <TableHead className="h-7 text-muted-foreground">Variable</TableHead>
                          <TableHead className="h-7 text-muted-foreground">Impact</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {blockingPageGaps.map((gap) => (
                          <TableRow key={gap.variable} className="border-yellow-100 dark:border-yellow-800/20">
                            <TableCell className="py-1">
                              <code className="rounded bg-yellow-100 px-1 py-0.5 dark:bg-yellow-900/30">{gap.variable}</code>
                            </TableCell>
                            <TableCell className="py-1 text-muted-foreground">{gap.reason}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </>
                )}

                {p.key === 'ip_intelligence' && (
                  <>
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-400">
                      The following AWAF IP intelligence categories have no equivalent XC threat category and will be skipped.
                    </p>
                    <Table className="mt-2 text-xs">
                      <TableHeader>
                        <TableRow className="border-yellow-200 dark:border-yellow-800/30">
                          <TableHead className="h-7 text-muted-foreground">Category</TableHead>
                          <TableHead className="h-7 text-muted-foreground">Impact</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {ipIntelGaps.map((gap) => (
                          <TableRow key={gap.category} className="border-yellow-100 dark:border-yellow-800/20">
                            <TableCell className="py-1 font-medium">{gap.category}</TableCell>
                            <TableCell className="py-1 text-muted-foreground">{gap.reason}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* 4. Gaps */}
      {(prot.none.length > 0 || untranslatable.custom_signature_count > 0) && (
        <Card>
          <CardHeader className="pb-0">
            <CardTitle className="flex items-center gap-2 text-lg">
              <ShieldAlert className="size-5 text-destructive" />
              Gaps
            </CardTitle>
            <CardDescription>
              These features have no direct XC equivalent. You will need to configure alternatives manually after conversion.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-3">
            {prot.none.includes('Brute Force') && (
              <div className="rounded-md border border-destructive/20 bg-destructive/5 p-4">
                <h3 className="text-sm font-semibold text-destructive">Brute Force</h3>
                <p className="mt-1 text-xs text-destructive/80">
                  <span className="font-medium">AWAF:</span> Detects login brute-force attacks by tracking failed attempts over a detection window.
                </p>
                <p className="mt-0.5 text-xs text-destructive/80">
                  <span className="font-medium">XC:</span> Rate limiting is available at the load balancer and service policy levels, but AWAF login-URL-based brute force config cannot be directly mapped.
                </p>
              </div>
            )}

            {prot.none.includes('Session Tracking') && (
              <div className="rounded-md border border-destructive/20 bg-destructive/5 p-4">
                <h3 className="text-sm font-semibold text-destructive">Session Tracking</h3>
                <p className="mt-1 text-xs text-destructive/80">
                  <span className="font-medium">AWAF:</span> Tracks user sessions to detect anomalies like session hijacking and session awareness.
                </p>
                <p className="mt-0.5 text-xs text-destructive/80">
                  <span className="font-medium">XC:</span> Client-side JavaScript challenge and fingerprinting exist, but these are configured at the load balancer level — not migrated from the AWAF policy.
                </p>
              </div>
            )}

            {untranslatable.custom_signature_count > 0 && (
              <div className="rounded-md border border-destructive/20 bg-destructive/5 p-4">
                <h3 className="text-sm font-semibold text-destructive">
                  Custom Signatures ({untranslatable.custom_signature_count})
                </h3>
                <p className="mt-1 text-xs text-destructive/80">
                  Custom AWAF signatures have no equivalent in XC WAF and will be omitted from the conversion.
                </p>
                {untranslatable.custom_signatures.length > 0 && (
                  <Table className="mt-2 text-xs">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="h-7 text-muted-foreground">ID</TableHead>
                        <TableHead className="h-7 text-muted-foreground">Name</TableHead>
                        <TableHead className="h-7 text-muted-foreground">Scope</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {untranslatable.custom_signatures.map((sig) => (
                        <TableRow key={sig.id}>
                          <TableCell className="py-1 font-mono">{sig.id}</TableCell>
                          <TableCell className="py-1">{sig.name}</TableCell>
                          <TableCell className="py-1 text-muted-foreground">{sig.scope}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            )}
          </CardContent>

          {warnings.length > 0 && (
            <CardContent className="pt-0">
              <Separator className="mb-3" />
              <h3 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Limit Warnings</h3>
              <div className="mt-2 space-y-2">
                {warnings.map((w) => (
                  <div key={w.resource} className="rounded-md border border-yellow-200 bg-yellow-50 px-3 py-2 dark:border-yellow-900/50 dark:bg-yellow-900/10">
                    <p className="text-xs text-yellow-800 dark:text-yellow-200">{w.message}</p>
                    <p className="mt-0.5 text-xs text-yellow-600 dark:text-yellow-400">Current: {w.count} — XC limit: {w.limit}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>
      )}
    </div>
  );
}
