import type { PolicyInfo, BotGap, BlockingPageGap, IpIntelGap } from '../types';

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

const STATUS_STYLES: Record<TranslationStatus, string> = {
  full: 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  partial: 'bg-yellow-50 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  none: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300',
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

      {enabledProtections.length > 0 && (
        <div className="mt-4 space-y-2">
          {(['full', 'partial', 'none'] as TranslationStatus[]).map((status) => {
            const items = grouped[status];
            if (items.length === 0) return null;
            return (
              <div key={status}>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {STATUS_LABELS[status]}
                </span>
                <div className="mt-1.5 flex flex-wrap gap-2">
                  {items.map((f) => (
                    <span
                      key={f.key}
                      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLES[status]}`}
                      title={f.note}
                    >
                      {f.label}
                    </span>
                  ))}
                </div>
                {status === 'partial' && botGaps.length > 0 && (
                  <div className="mt-2 ml-1 rounded-md border border-yellow-200 bg-yellow-50/50 p-3 dark:border-yellow-800/50 dark:bg-yellow-900/10">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400">
                          <th className="pb-1 font-medium">Category</th>
                          <th className="pb-1 font-medium">AWAF Action</th>
                          <th className="pb-1 font-medium">Gap</th>
                        </tr>
                      </thead>
                      <tbody className="text-gray-700 dark:text-gray-300">
                        {botGaps.map((gap) => (
                          <tr key={gap.category}>
                            <td className="py-0.5 font-medium">{gap.category}</td>
                            <td className="py-0.5">
                              <code className="rounded bg-yellow-100 px-1 py-0.5 text-xs dark:bg-yellow-900/30">
                                {gap.asm_action}
                              </code>
                            </td>
                            <td className="py-0.5 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {status === 'partial' && blockingPageGaps.length > 0 && (
                  <div className="mt-2 ml-1 rounded-md border border-yellow-200 bg-yellow-50/50 p-3 dark:border-yellow-800/50 dark:bg-yellow-900/10">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400">
                          <th className="pb-1 font-medium">Variable</th>
                          <th className="pb-1 font-medium">Gap</th>
                        </tr>
                      </thead>
                      <tbody className="text-gray-700 dark:text-gray-300">
                        {blockingPageGaps.map((gap) => (
                          <tr key={gap.variable}>
                            <td className="py-0.5">
                              <code className="rounded bg-yellow-100 px-1 py-0.5 text-xs dark:bg-yellow-900/30">
                                {gap.variable}
                              </code>
                            </td>
                            <td className="py-0.5 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {status === 'partial' && ipIntelGaps.length > 0 && (
                  <div className="mt-2 ml-1 rounded-md border border-yellow-200 bg-yellow-50/50 p-3 dark:border-yellow-800/50 dark:bg-yellow-900/10">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400">
                          <th className="pb-1 font-medium">Category</th>
                          <th className="pb-1 font-medium">Gap</th>
                        </tr>
                      </thead>
                      <tbody className="text-gray-700 dark:text-gray-300">
                        {ipIntelGaps.map((gap) => (
                          <tr key={gap.category}>
                            <td className="py-0.5 font-medium">{gap.category}</td>
                            <td className="py-0.5 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
