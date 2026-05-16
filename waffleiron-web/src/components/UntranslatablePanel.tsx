import type { UntranslatableSummary, BotGap } from '../types';

interface UntranslatablePanelProps {
  untranslatable: UntranslatableSummary;
  botGaps: BotGap[];
}

export default function UntranslatablePanel({ untranslatable, botGaps }: UntranslatablePanelProps) {
  const hasCustomSigs = untranslatable.custom_signatures.length > 0;
  const hasFeatures =
    untranslatable.session_tracking_enabled ||
    untranslatable.session_hijacking_enabled ||
    untranslatable.brute_force_enabled;
  const hasBotGaps = botGaps.length > 0;

  if (!hasCustomSigs && !hasFeatures && !hasBotGaps) return null;

  const unsupportedFeatures = [
    untranslatable.session_tracking_enabled && 'Session Tracking',
    untranslatable.session_hijacking_enabled && 'Session Hijacking Detection',
    untranslatable.brute_force_enabled && 'Brute Force Protection',
  ].filter(Boolean) as string[];

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
      <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
        Cannot Translate
      </h2>
      <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">
        These AWAF features have no equivalent in XC WAF and will be omitted from the conversion.
      </p>

      {unsupportedFeatures.length > 0 && (
        <div className="mb-4">
          <h3 className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
            Unsupported Features
          </h3>
          <div className="flex flex-wrap gap-2">
            {unsupportedFeatures.map((feat) => (
              <span
                key={feat}
                className="rounded-full bg-red-100 px-3 py-1 text-xs font-medium text-red-800 dark:bg-red-900/30 dark:text-red-300"
              >
                {feat}
              </span>
            ))}
          </div>
        </div>
      )}

      {hasCustomSigs && (
        <div className="mb-4">
          <h3 className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
            Custom Signatures ({untranslatable.custom_signatures.length})
          </h3>
          <div className="overflow-hidden rounded-md border border-gray-200 dark:border-gray-700">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-800/60">
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">ID</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">Name</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {untranslatable.custom_signatures.map((sig) => (
                  <tr key={sig.id}>
                    <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-gray-900 dark:text-gray-100">{sig.id}</td>
                    <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{sig.name}</td>
                    <td className="px-3 py-2 text-gray-500 dark:text-gray-400">{sig.scope}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {hasBotGaps && (
        <div>
          <h3 className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
            Bot Defense Gaps ({botGaps.length})
          </h3>
          <div className="overflow-hidden rounded-md border border-gray-200 dark:border-gray-700">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-800/60">
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">Category</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">ASM Action</th>
                  <th className="px-3 py-2 text-left text-xs font-medium uppercase text-gray-500 dark:text-gray-400">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {botGaps.map((gap) => (
                  <tr key={gap.category}>
                    <td className="px-3 py-2 font-medium text-gray-900 dark:text-gray-100">{gap.category}</td>
                    <td className="px-3 py-2">
                      <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                        {gap.asm_action}
                      </code>
                    </td>
                    <td className="px-3 py-2 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
