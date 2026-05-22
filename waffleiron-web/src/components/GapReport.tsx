import { useEffect, useState, useCallback, useMemo } from 'react';
import { AlertTriangle, Braces, Download, FileText, Lightbulb, Loader2 } from 'lucide-react';
import { getReport } from '../api';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from '@/components/ui/accordion';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from '@/components/ui/dropdown-menu';

interface GapReportData {
  policy_name: string;
  enforcement_mode: string;
  summary: {
    total: number;
    directly_translated: number;
    translated_with_loss: number;
    decisions_required: number;
    cannot_translate: number;
  };
  alarm_only_signatures: Array<{
    sig_id: number;
    description: string;
    scope: string;
    decision: string;
  }>;
  alarm_only_violations: Array<{
    violation: string;
    decision: string;
  }>;
  positive_security: {
    url_count: number;
    wildcard_url_count: number;
    parameter_count: number;
    constrained_parameter_count: number;
    file_type_count: number;
    cookie_count: number;
    mandatory_header_count: number;
    disallowed_file_type_count: number;
    url_method_restriction_count: number;
    global_method_restriction: boolean;
    translated: {
      filetype_deny_count: number;
      method_deny_count: number;
      filetype_gated: boolean;
      method_gated: boolean;
    };
  };
  untranslatable: {
    custom_signature_count: number;
    session_tracking_enabled: boolean;
    session_hijacking_enabled: boolean;
    brute_force_enabled: boolean;
    custom_signatures: Array<{
      id: string;
      name: string;
      pattern: string;
      scope: string;
    }>;
  };
  bot_gaps: Array<{
    category: string;
    asm_action: string;
    reason: string;
  }>;
  warnings: Array<{
    resource: string;
    count: number;
    limit: number;
    message: string;
  }>;
  manual_steps: Array<{
    feature: string;
    details: string;
  }>;
  xc_recommendations: Array<{
    feature: string;
    why: string;
  }>;
}

interface GapReportProps {
  sessionId: string;
}

function EmptySection() {
  return <p className="text-sm italic text-muted-foreground">None</p>;
}

function DecisionBadge({ decision }: { decision: string }) {
  const normalized = decision.toLowerCase();
  if (normalized === 'enforce') {
    return <Badge variant="outline" className="border-green-300 text-green-700 dark:border-green-700 dark:text-green-400">Enforce</Badge>;
  }
  return <Badge variant="secondary">{decision}</Badge>;
}

function StatusBadge({ enabled, label }: { enabled: boolean; label: string }) {
  if (enabled) {
    return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300">{label}: Enabled</Badge>;
  }
  return <Badge variant="secondary">{label}: Disabled</Badge>;
}

function triggerDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function GapReport({ sessionId }: GapReportProps) {
  const [data, setData] = useState<GapReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchReport() {
      setLoading(true);
      setError(null);
      try {
        const json = await getReport(sessionId, 'json') as unknown as GapReportData;
        if (!cancelled) setData(json);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : 'Failed to load gap report',
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchReport();
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  const handleDownloadMarkdown = useCallback(async () => {
    try {
      const markdown = await getReport(sessionId, 'markdown');
      triggerDownload(markdown, `gap_report-${sessionId}.md`, 'text/markdown');
    } catch {
      // fetch error — silently ignore for download
    }
  }, [sessionId]);

  const handleDownloadJson = useCallback(() => {
    if (!data) return;
    triggerDownload(JSON.stringify(data, null, 2), `gap_report-${sessionId}.json`, 'application/json');
  }, [data, sessionId]);

  const defaultOpenSections = useMemo(() => {
    if (!data) return [];
    const open: string[] = [];
    if (data.summary.total > 0) open.push('summary');
    if (data.alarm_only_signatures.length > 0) open.push('alarm-sigs');
    if (data.alarm_only_violations.length > 0) open.push('alarm-viols');

    const ps = data.positive_security;
    const hasPositiveData = ps.url_count > 0 || ps.wildcard_url_count > 0 || ps.parameter_count > 0 ||
      ps.constrained_parameter_count > 0 || ps.file_type_count > 0 || ps.cookie_count > 0 ||
      ps.mandatory_header_count > 0 || ps.disallowed_file_type_count > 0 ||
      ps.url_method_restriction_count > 0 || ps.global_method_restriction ||
      ps.translated.filetype_deny_count > 0 || ps.translated.method_deny_count > 0;
    if (hasPositiveData) open.push('positive-security');

    if (data.untranslatable.custom_signatures.length > 0) open.push('custom-sigs');

    const hasUntranslatable = data.untranslatable.session_tracking_enabled ||
      data.untranslatable.session_hijacking_enabled || data.untranslatable.brute_force_enabled;
    if (hasUntranslatable) open.push('untranslatable');

    if (data.bot_gaps.length > 0) open.push('bot-gaps');
    if (data.warnings.length > 0) open.push('warnings');
    if (data.manual_steps.length > 0) open.push('manual-steps');
    if (data.xc_recommendations.length > 0) open.push('xc-recs');
    return open;
  }, [data]);

  if (loading) {
    return (
      <Card className="px-5 py-8">
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          <span className="text-sm text-muted-foreground">
            Loading gap report...
          </span>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="border-destructive bg-destructive/10 px-5 py-4">
        <p className="text-sm text-destructive">{error}</p>
      </Card>
    );
  }

  if (!data) return null;

  const { summary, positive_security: ps, untranslatable } = data;

  const posCannotTranslate = [
    { feature: 'URLs', count: ps.url_count },
    { feature: 'Wildcard URLs', count: ps.wildcard_url_count },
    { feature: 'Parameters', count: ps.parameter_count },
    { feature: 'Constrained parameters', count: ps.constrained_parameter_count },
    { feature: 'File types (allow list)', count: ps.file_type_count },
    { feature: 'Cookies', count: ps.cookie_count },
    { feature: 'Mandatory headers', count: ps.mandatory_header_count },
  ].filter((r) => r.count > 0);

  const posTranslated = [
    ps.translated.filetype_deny_count > 0 && { feature: 'Disallowed file types', count: ps.translated.filetype_deny_count },
    ps.translated.method_deny_count > 0 && { feature: 'Disallowed methods', count: ps.translated.method_deny_count },
  ].filter(Boolean) as Array<{ feature: string; count: number }>;

  return (
    <Card className="gap-0 overflow-hidden py-0">
      <div className="flex items-center justify-between border-b bg-muted/60 px-4 py-2">
        <span className="text-sm font-semibold text-muted-foreground">Gap Report</span>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button type="button" variant="ghost" size="xs">
              <Download className="h-3.5 w-3.5" />
              Download
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={handleDownloadMarkdown}>
              <FileText className="h-4 w-4" />
              Markdown (.md)
            </DropdownMenuItem>
            <DropdownMenuItem onClick={handleDownloadJson}>
              <Braces className="h-4 w-4" />
              JSON (.json)
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <CardContent className="py-4">
        <p className="mb-4 text-sm text-muted-foreground">
          Source policy: <strong className="text-foreground">{data.policy_name}</strong>
          {' | '}
          Enforcement mode: <strong className="text-foreground">{data.enforcement_mode}</strong>
        </p>

        <Accordion type="multiple" defaultValue={defaultOpenSections}>
          {/* Summary */}
          <AccordionItem value="summary">
            <AccordionTrigger>Summary</AccordionTrigger>
            <AccordionContent>
              {summary.total === 0 ? <EmptySection /> : (
                <div className="rounded-md border">
                  <Table>
                    <TableBody>
                      <TableRow>
                        <TableCell className="font-medium">Total settings</TableCell>
                        <TableCell className="text-right">{summary.total}</TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">Directly translated</TableCell>
                        <TableCell className="text-right">
                          <Badge className="bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">{summary.directly_translated}</Badge>
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">Translated with loss</TableCell>
                        <TableCell className="text-right">
                          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300">{summary.translated_with_loss}</Badge>
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">Decisions required</TableCell>
                        <TableCell className="text-right">
                          <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300">{summary.decisions_required}</Badge>
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className="font-medium">Cannot translate</TableCell>
                        <TableCell className="text-right">
                          <Badge variant="destructive">{summary.cannot_translate}</Badge>
                        </TableCell>
                      </TableRow>
                    </TableBody>
                  </Table>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Alarm-Only Signatures */}
          <AccordionItem value="alarm-sigs">
            <AccordionTrigger>Alarm-Only Signatures</AccordionTrigger>
            <AccordionContent>
              {data.alarm_only_signatures.length === 0 ? <EmptySection /> : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted dark:bg-white/10">
                        <TableHead className="text-xs uppercase tracking-wider">ID</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Description</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Scope</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Decision</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.alarm_only_signatures.map((sig) => (
                        <TableRow key={sig.sig_id}>
                          <TableCell>{sig.sig_id}</TableCell>
                          <TableCell>{sig.description}</TableCell>
                          <TableCell>{sig.scope}</TableCell>
                          <TableCell><DecisionBadge decision={sig.decision} /></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Alarm-Only Violations */}
          <AccordionItem value="alarm-viols">
            <AccordionTrigger>Alarm-Only Violations</AccordionTrigger>
            <AccordionContent>
              {data.alarm_only_violations.length === 0 ? <EmptySection /> : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted dark:bg-white/10">
                        <TableHead className="text-xs uppercase tracking-wider">Violation</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Decision</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.alarm_only_violations.map((v) => (
                        <TableRow key={v.violation}>
                          <TableCell>{v.violation}</TableCell>
                          <TableCell><DecisionBadge decision={v.decision} /></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Positive Security */}
          <AccordionItem value="positive-security">
            <AccordionTrigger>Positive Security</AccordionTrigger>
            <AccordionContent>
              <div className="space-y-4">
                {posTranslated.length > 0 && (
                  <div>
                    <h4 className="mb-2 text-sm font-medium">Translated to Service Policy DENY Rules</h4>
                    <div className="rounded-md border">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-muted dark:bg-white/10">
                            <TableHead className="text-xs uppercase tracking-wider">Feature</TableHead>
                            <TableHead className="text-xs uppercase tracking-wider">Count</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {posTranslated.map((r) => (
                            <TableRow key={r.feature}>
                              <TableCell>{r.feature}</TableCell>
                              <TableCell>{r.count}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                )}

                {(ps.translated.filetype_gated || ps.translated.method_gated) && (
                  <Alert className="border-yellow-200 bg-yellow-50 dark:border-yellow-700/40 dark:bg-yellow-900/20">
                    <AlertTriangle className="text-yellow-600 dark:text-yellow-400" />
                    <AlertTitle>Enforcement Gating</AlertTitle>
                    <AlertDescription>
                      {ps.translated.filetype_gated && <p>File type deny rules are gated behind allowed file types being configured.</p>}
                      {ps.translated.method_gated && <p>Method deny rules are gated behind allowed methods being configured.</p>}
                    </AlertDescription>
                  </Alert>
                )}

                <div>
                  <h4 className="mb-2 text-sm font-medium">Cannot Translate</h4>
                  {posCannotTranslate.length === 0 ? <EmptySection /> : (
                    <div className="rounded-md border">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-muted dark:bg-white/10">
                            <TableHead className="text-xs uppercase tracking-wider">Feature</TableHead>
                            <TableHead className="text-xs uppercase tracking-wider">Count</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {posCannotTranslate.map((r) => (
                            <TableRow key={r.feature}>
                              <TableCell>{r.feature}</TableCell>
                              <TableCell>{r.count}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>

          {/* Custom Signatures */}
          <AccordionItem value="custom-sigs">
            <AccordionTrigger>Custom Signatures</AccordionTrigger>
            <AccordionContent>
              {untranslatable.custom_signatures.length === 0 ? <EmptySection /> : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted dark:bg-white/10">
                        <TableHead className="text-xs uppercase tracking-wider">ID</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Name</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Pattern</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Scope</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {untranslatable.custom_signatures.map((cs) => (
                        <TableRow key={cs.id}>
                          <TableCell>{cs.id}</TableCell>
                          <TableCell>{cs.name}</TableCell>
                          <TableCell>{cs.pattern}</TableCell>
                          <TableCell>{cs.scope}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Untranslatable Features */}
          <AccordionItem value="untranslatable">
            <AccordionTrigger>Untranslatable Features</AccordionTrigger>
            <AccordionContent>
              {!untranslatable.session_tracking_enabled && !untranslatable.session_hijacking_enabled && !untranslatable.brute_force_enabled ? (
                <EmptySection />
              ) : (
                <div className="flex flex-wrap gap-2">
                  <StatusBadge enabled={untranslatable.session_tracking_enabled} label="Session tracking" />
                  <StatusBadge enabled={untranslatable.session_hijacking_enabled} label="Session hijacking" />
                  <StatusBadge enabled={untranslatable.brute_force_enabled} label="Brute force" />
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Bot Protection Gaps */}
          <AccordionItem value="bot-gaps">
            <AccordionTrigger>Bot Protection Gaps</AccordionTrigger>
            <AccordionContent>
              {data.bot_gaps.length === 0 ? <EmptySection /> : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted dark:bg-white/10">
                        <TableHead className="text-xs uppercase tracking-wider">Category</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">AWAF Action</TableHead>
                        <TableHead className="text-xs uppercase tracking-wider">Reason</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.bot_gaps.map((gap) => (
                        <TableRow key={gap.category}>
                          <TableCell>{gap.category}</TableCell>
                          <TableCell>{gap.asm_action}</TableCell>
                          <TableCell>{gap.reason}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Warnings */}
          <AccordionItem value="warnings">
            <AccordionTrigger>Warnings</AccordionTrigger>
            <AccordionContent>
              {data.warnings.length === 0 ? <EmptySection /> : (
                <div className="space-y-2">
                  {data.warnings.map((w) => (
                    <Alert
                      key={w.resource}
                      className="border-yellow-200 bg-yellow-50 dark:border-yellow-700/40 dark:bg-yellow-900/20"
                    >
                      <AlertTriangle className="text-yellow-600 dark:text-yellow-400" />
                      <AlertTitle>{w.resource} ({w.count}/{w.limit})</AlertTitle>
                      <AlertDescription>{w.message}</AlertDescription>
                    </Alert>
                  ))}
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* Manual Steps Required */}
          <AccordionItem value="manual-steps">
            <AccordionTrigger>Manual Steps Required</AccordionTrigger>
            <AccordionContent>
              {data.manual_steps.length === 0 ? <EmptySection /> : (
                <div className="space-y-2">
                  {data.manual_steps.map((step) => (
                    <Alert
                      key={step.feature}
                      className="border-blue-200 bg-blue-50 dark:border-blue-700/40 dark:bg-blue-900/20"
                    >
                      <AlertTitle>{step.feature}</AlertTitle>
                      <AlertDescription>{step.details}</AlertDescription>
                    </Alert>
                  ))}
                </div>
              )}
            </AccordionContent>
          </AccordionItem>

          {/* XC Feature Recommendations */}
          <AccordionItem value="xc-recs">
            <AccordionTrigger>XC Feature Recommendations</AccordionTrigger>
            <AccordionContent>
              {data.xc_recommendations.length === 0 ? <EmptySection /> : (
                <div className="space-y-2">
                  {data.xc_recommendations.map((rec) => (
                    <Alert
                      key={rec.feature}
                      className="border-green-200 bg-green-50 dark:border-green-700/40 dark:bg-green-900/20"
                    >
                      <Lightbulb className="text-green-600 dark:text-green-400" />
                      <AlertTitle>{rec.feature}</AlertTitle>
                      <AlertDescription>{rec.why}</AlertDescription>
                    </Alert>
                  ))}
                </div>
              )}
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}
