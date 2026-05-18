import type { PolicyInfo, BotGap, BlockingPageGap, IpIntelGap } from '../types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';

interface PolicyInfoCardProps {
  info: PolicyInfo;
  botGaps: BotGap[];
  blockingPageGaps: BlockingPageGap[];
  ipIntelGaps: IpIntelGap[];
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

const STATUS_BADGE_VARIANT: Record<TranslationStatus, { className: string }> = {
  full: { className: 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300' },
  partial: { className: 'bg-yellow-50 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300' },
  none: { className: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300' },
};

const STATUS_LABELS: Record<TranslationStatus, string> = {
  full: 'Fully translates',
  partial: 'Partially translates',
  none: 'Cannot translate',
};

export default function PolicyInfoCard({ info, botGaps, blockingPageGaps, ipIntelGaps }: PolicyInfoCardProps) {
  const isBlocking = info.enforcement_mode === 'blocking';

  const enabledProtections = PROTECTIONS
    .filter((f) => info.features[f.key])
    .map((f) => {
      let status = f.base;
      let note: string | undefined;

      if (f.key === 'bot_defense' && botGaps.length > 0) {
        status = 'partial';
        const actions = [...new Set(botGaps.map((g) => g.asm_action))].join(', ');
        note = `${actions} actions have no XC equivalent`;
      } else if (f.key === 'blocking_page' && blockingPageGaps.length > 0) {
        status = 'partial';
        const vars = blockingPageGaps.map((g) => g.variable).join(', ');
        note = `Unsupported template variables: ${vars}`;
      } else if (f.key === 'ip_intelligence' && ipIntelGaps.length > 0) {
        status = 'partial';
        const cats = ipIntelGaps.map((g) => g.category).join(', ');
        note = `Unmapped categories: ${cats}`;
      }

      return { ...f, status, note };
    });

  const grouped = {
    full: enabledProtections.filter((f) => f.status === 'full'),
    partial: enabledProtections.filter((f) => f.status === 'partial'),
    none: enabledProtections.filter((f) => f.status === 'none'),
  };

  return (
    <Card>
      <CardHeader className="pb-0">
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="text-lg">{info.name}</CardTitle>
            <CardDescription className="mt-0.5">
              Encoding: {info.encoding}
            </CardDescription>
          </div>
          <Badge
            variant="outline"
            className={
              isBlocking
                ? 'bg-green-100 text-green-800 uppercase tracking-wide font-semibold dark:bg-green-900/30 dark:text-green-300'
                : 'bg-yellow-100 text-yellow-800 uppercase tracking-wide font-semibold dark:bg-yellow-900/30 dark:text-yellow-300'
            }
          >
            {info.enforcement_mode}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="grid grid-cols-3 gap-x-6 gap-y-2 text-sm">
          <div>
            <span className="text-muted-foreground">Signature Accuracy</span>
            <p className="font-medium text-foreground capitalize">
              {info.signature_accuracy.replace('_', ' + ')}
            </p>
          </div>
          <div>
            <span className="text-muted-foreground">Staging</span>
            <p className="font-medium text-foreground">
              {info.staging_enabled ? 'Enabled' : 'Disabled'}
            </p>
          </div>
          <div>
            <span className="text-muted-foreground">Threat Campaigns</span>
            <p className="font-medium text-foreground">
              {info.threat_campaigns_enabled ? 'Enabled' : 'Disabled'}
            </p>
          </div>
        </div>

        {enabledProtections.length > 0 && (
          <div className="space-y-2">
            {(['full', 'partial', 'none'] as TranslationStatus[]).map((status) => {
              const items = grouped[status];
              if (items.length === 0) return null;
              return (
                <div key={status}>
                  <span className="text-sm text-muted-foreground">
                    {STATUS_LABELS[status]}
                  </span>
                  <div className="mt-1.5 flex flex-wrap gap-2">
                    {items.map((f) => (
                      <Badge
                        key={f.key}
                        variant="secondary"
                        className={STATUS_BADGE_VARIANT[status].className}
                        title={f.note}
                      >
                        {f.label}
                      </Badge>
                    ))}
                  </div>
                  {status === 'partial' && botGaps.length > 0 && (
                    <div className="mt-2 ml-1 rounded-md border border-yellow-200 bg-yellow-50/50 p-3 dark:border-yellow-800/50 dark:bg-yellow-900/10">
                      <Table className="text-xs">
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
                                <code className="rounded bg-yellow-100 px-1 py-0.5 text-xs dark:bg-yellow-900/30">
                                  {gap.asm_action}
                                </code>
                              </TableCell>
                              <TableCell className="py-1 text-muted-foreground">{gap.reason}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                  {status === 'partial' && blockingPageGaps.length > 0 && (
                    <div className="mt-2 ml-1 rounded-md border border-yellow-200 bg-yellow-50/50 p-3 dark:border-yellow-800/50 dark:bg-yellow-900/10">
                      <Table className="text-xs">
                        <TableHeader>
                          <TableRow className="border-yellow-200 dark:border-yellow-800/30">
                            <TableHead className="h-7 text-muted-foreground">Variable</TableHead>
                            <TableHead className="h-7 text-muted-foreground">Gap</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {blockingPageGaps.map((gap) => (
                            <TableRow key={gap.variable} className="border-yellow-100 dark:border-yellow-800/20">
                              <TableCell className="py-1">
                                <code className="rounded bg-yellow-100 px-1 py-0.5 text-xs dark:bg-yellow-900/30">
                                  {gap.variable}
                                </code>
                              </TableCell>
                              <TableCell className="py-1 text-muted-foreground">{gap.reason}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                  {status === 'partial' && ipIntelGaps.length > 0 && (
                    <div className="mt-2 ml-1 rounded-md border border-yellow-200 bg-yellow-50/50 p-3 dark:border-yellow-800/50 dark:bg-yellow-900/10">
                      <Table className="text-xs">
                        <TableHeader>
                          <TableRow className="border-yellow-200 dark:border-yellow-800/30">
                            <TableHead className="h-7 text-muted-foreground">Category</TableHead>
                            <TableHead className="h-7 text-muted-foreground">Gap</TableHead>
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
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
