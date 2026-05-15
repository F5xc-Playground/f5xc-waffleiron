import type { PolicyInfo, BotGap } from '../types';

interface PolicyInfoCardProps {
  info: PolicyInfo;
  botGaps: BotGap[];
}

type TranslationStatus = 'full' | 'partial' | 'none';

const FEATURES: { key: string; label: string; base: TranslationStatus }[] = [
  { key: 'blocking_page', label: 'Custom Blocking Page', base: 'full' },
  { key: 'bot_defense', label: 'Bot Defense', base: 'full' },
  { key: 'geolocation', label: 'Geolocation', base: 'full' },
  { key: 'ip_intelligence', label: 'IP Intelligence', base: 'full' },
  { key: 'data_guard', label: 'Data Guard', base: 'full' },
  { key: 'csrf', label: 'CSRF Protection', base: 'full' },
  { key: 'brute_force', label: 'Brute Force', base: 'none' },
  { key: 'session_tracking', label: 'Session Tracking', base: 'none' },
];

const STATUS_STYLES: Record<TranslationStatus, { pill: string; icon: string }> = {
  full: {
    pill: 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    icon: 'M5 13l4 4L19 7',
  },
  partial: {
    pill: 'bg-yellow-50 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    icon: 'M12 9v2m0 4h.01',
  },
  none: {
    pill: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    icon: 'M6 18L18 6M6 6l12 12',
  },
};

const STATUS_LABELS: Record<TranslationStatus, string> = {
  full: 'Translates to XC',
  partial: 'Partially translates',
  none: 'No XC equivalent',
};

export default function PolicyInfoCard({ info, botGaps }: PolicyInfoCardProps) {
  const isBlocking = info.enforcement_mode === 'blocking';

  const enabledFeatures = FEATURES
    .filter((f) => info.features[f.key])
    .map((f) => {
      let status = f.base;
      let note: string | undefined;

      if (f.key === 'bot_defense' && botGaps.length > 0) {
        status = 'partial';
        const actions = [...new Set(botGaps.map((g) => g.asm_action))].join(', ');
        note = `${actions} actions have no XC equivalent`;
      }

      return { ...f, status, note };
    });

  const grouped = {
    full: enabledFeatures.filter((f) => f.status === 'full'),
    partial: enabledFeatures.filter((f) => f.status === 'partial'),
    none: enabledFeatures.filter((f) => f.status === 'none'),
  };

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {info.name}
          </h2>
          <p className="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
            Encoding: {info.encoding}
          </p>
        </div>
        <span
          className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${
            isBlocking
              ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
              : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300'
          }`}
        >
          {info.enforcement_mode}
        </span>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-x-6 gap-y-2 text-sm">
        <div>
          <span className="text-gray-500 dark:text-gray-400">Signature Accuracy</span>
          <p className="font-medium text-gray-900 dark:text-white capitalize">
            {info.signature_accuracy.replace('_', ' + ')}
          </p>
        </div>
        <div>
          <span className="text-gray-500 dark:text-gray-400">Staging</span>
          <p className="font-medium text-gray-900 dark:text-white">
            {info.staging_enabled ? 'Enabled' : 'Disabled'}
          </p>
        </div>
        <div>
          <span className="text-gray-500 dark:text-gray-400">Threat Campaigns</span>
          <p className="font-medium text-gray-900 dark:text-white">
            {info.threat_campaigns_enabled ? 'Enabled' : 'Disabled'}
          </p>
        </div>
      </div>

      {enabledFeatures.length > 0 && (
        <div className="mt-4 space-y-2">
          {(['full', 'partial', 'none'] as TranslationStatus[]).map((status) => {
            const items = grouped[status];
            if (items.length === 0) return null;
            const styles = STATUS_STYLES[status];

            return (
              <div key={status}>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {STATUS_LABELS[status]}
                </span>
                <div className="mt-1.5 flex flex-wrap gap-2">
                  {items.map((f) => (
                    <span
                      key={f.key}
                      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${styles.pill}`}
                      title={f.note}
                    >
                      <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d={styles.icon} />
                      </svg>
                      {f.label}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
