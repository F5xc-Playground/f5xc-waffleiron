import { AlertTriangle } from 'lucide-react';
import type { UntranslatableSummary, LimitWarning } from '../types';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';

interface TranslatedWithLossPanelProps {
  untranslatable: UntranslatableSummary;
  warnings: LimitWarning[];
}

const LOSS_ITEMS: {
  key: keyof UntranslatableSummary;
  label: string;
  asmDescription: string;
  xcAlternative: string;
}[] = [
  {
    key: 'session_tracking_enabled',
    label: 'Session Tracking',
    asmDescription: 'Tracks user sessions to detect anomalies like session hijacking and session awareness.',
    xcAlternative: 'XC has client-side JavaScript challenge and fingerprinting, but these are configured at the load balancer level — not migrated from the AWAF policy.',
  },
  {
    key: 'brute_force_enabled',
    label: 'Brute Force Protection',
    asmDescription: 'Detects login brute-force attacks by tracking failed attempts over a detection window.',
    xcAlternative: 'XC supports rate limiting at the load balancer and service policy levels, but AWAF login-URL-based brute force config cannot be directly mapped.',
  },
];

export default function TranslatedWithLossPanel({ untranslatable, warnings }: TranslatedWithLossPanelProps) {
  const activeItems = LOSS_ITEMS.filter((item) => untranslatable[item.key]);
  const hasWarnings = warnings.length > 0;

  if (activeItems.length === 0 && !hasWarnings) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">
          Translated with Loss
        </CardTitle>
        <CardDescription>
          These features exist in your AWAF policy and XC has related capabilities, but the specific configuration cannot be automatically migrated. You will need to configure these manually in XC after the conversion.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {activeItems.length > 0 && (
          <div className="space-y-3">
            {activeItems.map((item) => (
              <Alert
                key={item.key}
                className="border-yellow-200 bg-yellow-50 dark:border-yellow-700/40 dark:bg-yellow-900/20"
              >
                <AlertTriangle className="text-yellow-600 dark:text-yellow-400" />
                <AlertTitle className="text-sm font-semibold text-yellow-800 dark:text-yellow-300">
                  {item.label}
                </AlertTitle>
                <AlertDescription>
                  <p className="text-sm text-foreground">
                    <span className="font-semibold text-yellow-600 dark:text-yellow-400">AWAF:</span> {item.asmDescription}
                  </p>
                  <p className="mt-0.5 text-sm text-foreground">
                    <span className="font-semibold text-yellow-600 dark:text-yellow-400">XC:</span> {item.xcAlternative}
                  </p>
                </AlertDescription>
              </Alert>
            ))}
          </div>
        )}

        {hasWarnings && (
          <div>
            <h3 className="mb-2 text-sm font-medium text-foreground">
              Limit Warnings
            </h3>
            <div className="space-y-2">
              {warnings.map((w) => (
                <Alert
                  key={w.resource}
                  className="border-yellow-200 bg-yellow-50 dark:border-yellow-700/40 dark:bg-yellow-900/20"
                >
                  <AlertTitle className="text-sm text-foreground">
                    {w.message}
                  </AlertTitle>
                  <AlertDescription className="text-sm text-muted-foreground">
                    Current: {w.count} — XC limit: {w.limit}
                  </AlertDescription>
                </Alert>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
