import type { UntranslatableSummary, LimitWarning } from '../types';

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
    <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
      <h2 className="mb-1 text-lg font-semibold text-gray-900 dark:text-white">
        Translated with Loss
      </h2>
      <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">
        These features exist in your AWAF policy and XC has related capabilities, but the specific configuration cannot be automatically migrated. You will need to configure these manually in XC after the conversion.
      </p>

      {activeItems.length > 0 && (
        <div className="space-y-3">
          {activeItems.map((item) => (
            <div
              key={item.key}
              className="rounded-md border border-yellow-200 bg-yellow-50 px-4 py-3 dark:border-yellow-900/50 dark:bg-yellow-900/10"
            >
              <div className="flex items-start gap-2">
                <svg className="mt-0.5 h-4 w-4 shrink-0 text-yellow-600 dark:text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                    {item.label}
                  </p>
                  <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-300">
                    <span className="font-medium">ASM:</span> {item.asmDescription}
                  </p>
                  <p className="mt-0.5 text-xs text-yellow-700 dark:text-yellow-300">
                    <span className="font-medium">XC:</span> {item.xcAlternative}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {hasWarnings && (
        <div className={activeItems.length > 0 ? 'mt-4' : ''}>
          <h3 className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
            Limit Warnings
          </h3>
          <div className="space-y-2">
            {warnings.map((w) => (
              <div
                key={w.resource}
                className="rounded-md border border-amber-200 bg-amber-50 px-4 py-2.5 dark:border-amber-900/50 dark:bg-amber-900/10"
              >
                <p className="text-sm text-amber-800 dark:text-amber-200">
                  {w.message}
                </p>
                <p className="mt-0.5 text-xs text-amber-600 dark:text-amber-400">
                  Current: {w.count} — XC limit: {w.limit}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
