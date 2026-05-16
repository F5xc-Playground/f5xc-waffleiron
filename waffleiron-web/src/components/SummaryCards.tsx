import type { ConversionSummary, PolicyInfo, PolicyOverrides, BotGap, BlockingPageGap, IpIntelGap, UntranslatableSummary, LimitWarning } from '../types';

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

const selectClass = 'rounded border border-gray-300 bg-white px-2 py-1 text-sm font-medium text-gray-900 dark:border-gray-600 dark:bg-gray-700 dark:text-white';

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
      <div className="flex items-center justify-center gap-3 rounded-lg border border-gray-200 bg-white px-6 py-4 shadow-sm dark:border-gray-700 dark:bg-gray-800">
        <span className="text-4xl font-bold text-green-600 dark:text-green-400">{pct}%</span>
        <span className="text-sm text-gray-500 dark:text-gray-400">
          translation coverage ({translated}/{summary.total} items)
        </span>
      </div>

      {/* 2. Policy Overview (merged Source + Translated) */}
      <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Policy Overview</h2>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Source: <span className="font-medium text-gray-900 dark:text-white">{policyInfo.name}</span>
              <span className="mx-2 text-gray-300 dark:text-gray-600">|</span>
              Encoding: <span className="font-medium text-gray-900 dark:text-white">{policyInfo.encoding}</span>
            </p>
          </div>
          {hasOverrides && (
            <span className="shrink-0 rounded-full bg-indigo-100 px-2.5 py-0.5 text-xs font-medium text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300">
              Modified
            </span>
          )}
        </div>

        {/* Editable Detection Settings */}
        <div className="mt-4">
          <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Detection Settings</h3>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-4 text-sm sm:grid-cols-4">
            <div>
              <label className="block text-gray-500 dark:text-gray-400">Enforcement</label>
              <select
                value={effectiveMode}
                onChange={(e) => setOverride('enforcement_mode', e.target.value)}
                className={`mt-1.5 block ${selectClass}`}
              >
                <option value="blocking">Blocking</option>
                <option value="transparent">Transparent</option>
              </select>
            </div>
            <div>
              <label className="block text-gray-500 dark:text-gray-400">Accuracy</label>
              <select
                value={effectiveAccuracy}
                onChange={(e) => setOverride('signature_accuracy', e.target.value)}
                className={`mt-1.5 block ${selectClass}`}
              >
                <option value="high">High</option>
                <option value="high_medium">High + Medium</option>
                <option value="all">All</option>
              </select>
            </div>
            <div>
              <label className="block text-gray-500 dark:text-gray-400">Staging</label>
              <select
                value={effectiveStaging ? 'true' : 'false'}
                onChange={(e) => setOverride('staging_enabled', e.target.value === 'true')}
                className={`mt-1.5 block ${selectClass}`}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </div>
            <div>
              <label className="block text-gray-500 dark:text-gray-400">Threat Campaigns</label>
              <select
                value={effectiveThreatCampaigns ? 'true' : 'false'}
                onChange={(e) => setOverride('threat_campaigns_enabled', e.target.value === 'true')}
                className={`mt-1.5 block ${selectClass}`}
              >
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
              </select>
            </div>
          </div>
        </div>

        {/* Protections */}
        {prot.full.length > 0 && (
          <div className="mt-4">
            <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Protections</h3>
            <div className="mt-1.5 flex flex-wrap gap-2">
              {prot.full.map((label) => (
                <span key={label} className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  {label}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Attack Types */}
        {enabledSigSets.length > 0 && (
          <div className="mt-4">
            <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">
              Attack Types ({enabledSigSets.length})
            </h3>
            <div className="mt-1.5 flex flex-wrap gap-2">
              {enabledSigSets.map((name) => (
                <span key={name} className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  {name}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Service Policy Rules */}
        {((policyInfo.entity_counts.whitelist_ips ?? 0) > 0 || policyInfo.features.geolocation || policyInfo.features.ip_intelligence) && (
          <div className="mt-4">
            <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Service Policy Rules</h3>
            <div className="mt-1.5 flex flex-wrap gap-2">
              {(policyInfo.entity_counts.whitelist_ips ?? 0) > 0 && (
                <span className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  {policyInfo.entity_counts.whitelist_ips} IP allow rule{policyInfo.entity_counts.whitelist_ips !== 1 ? 's' : ''}
                </span>
              )}
              {policyInfo.features.geolocation && (
                <span className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  Geolocation deny rules
                </span>
              )}
              {policyInfo.features.ip_intelligence && (
                <span className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  IP intelligence deny rules
                </span>
              )}
            </div>
          </div>
        )}

        {/* Exclusion & Violation Rules */}
        {((policyInfo.entity_counts.signature_overrides ?? 0) > 0 || (policyInfo.entity_counts.violations ?? 0) > 0) && (
          <div className="mt-4">
            <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Rules</h3>
            <div className="mt-1.5 flex flex-wrap gap-2">
              {(policyInfo.entity_counts.signature_overrides ?? 0) > 0 && (
                <span className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  {policyInfo.entity_counts.signature_overrides} global signature exclusion{policyInfo.entity_counts.signature_overrides !== 1 ? 's' : ''}
                </span>
              )}
              {(policyInfo.entity_counts.violations ?? 0) > 0 && (
                <span className="rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-medium text-green-700 dark:bg-green-900/30 dark:text-green-300">
                  {policyInfo.entity_counts.violations} violation setting{policyInfo.entity_counts.violations !== 1 ? 's' : ''}
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* 3. Partial */}
      {prot.partial.length > 0 && (
        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Partial</h2>

          <div className="mt-4 space-y-4">
            {prot.partial.map((p) => (
              <div key={p.key} className="rounded-md border border-yellow-100 bg-yellow-50/50 p-4 dark:border-yellow-800/30 dark:bg-yellow-900/10">
                <h3 className="text-sm font-semibold text-yellow-800 dark:text-yellow-300">{p.label}</h3>

                {p.key === 'bot_defense' && (
                  <>
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-400">
                      Bot categories are translated, but the following AWAF actions have no XC equivalent and will be omitted.
                    </p>
                    <table className="mt-2 w-full text-xs">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400">
                          <th className="pb-1 pr-4 font-medium">Category</th>
                          <th className="pb-1 pr-4 font-medium">AWAF Action</th>
                          <th className="pb-1 font-medium">Gap</th>
                        </tr>
                      </thead>
                      <tbody className="text-gray-700 dark:text-gray-300">
                        {botGaps.map((gap) => (
                          <tr key={gap.category}>
                            <td className="py-0.5 pr-4 font-medium">{gap.category}</td>
                            <td className="py-0.5 pr-4">
                              <code className="rounded bg-yellow-100 px-1 py-0.5 dark:bg-yellow-900/30">{gap.asm_action}</code>
                            </td>
                            <td className="py-0.5 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}

                {p.key === 'blocking_page' && (
                  <>
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-400">
                      XC only supports <code className="rounded bg-yellow-100 px-1 dark:bg-yellow-900/30">{'{{request_id}}'}</code> in custom blocking pages. The following AWAF variables will render as literal text.
                    </p>
                    <table className="mt-2 w-full text-xs">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400">
                          <th className="pb-1 pr-4 font-medium">Variable</th>
                          <th className="pb-1 font-medium">Impact</th>
                        </tr>
                      </thead>
                      <tbody className="text-gray-700 dark:text-gray-300">
                        {blockingPageGaps.map((gap) => (
                          <tr key={gap.variable}>
                            <td className="py-0.5 pr-4">
                              <code className="rounded bg-yellow-100 px-1 py-0.5 dark:bg-yellow-900/30">{gap.variable}</code>
                            </td>
                            <td className="py-0.5 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}

                {p.key === 'ip_intelligence' && (
                  <>
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-400">
                      The following AWAF IP intelligence categories have no equivalent XC threat category and will be skipped.
                    </p>
                    <table className="mt-2 w-full text-xs">
                      <thead>
                        <tr className="text-left text-gray-500 dark:text-gray-400">
                          <th className="pb-1 pr-4 font-medium">Category</th>
                          <th className="pb-1 font-medium">Impact</th>
                        </tr>
                      </thead>
                      <tbody className="text-gray-700 dark:text-gray-300">
                        {ipIntelGaps.map((gap) => (
                          <tr key={gap.category}>
                            <td className="py-0.5 pr-4 font-medium">{gap.category}</td>
                            <td className="py-0.5 text-gray-500 dark:text-gray-400">{gap.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. Gaps */}
      {(prot.none.length > 0 || untranslatable.custom_signature_count > 0) && (
        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Gaps</h2>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            These features have no direct XC equivalent. You will need to configure alternatives manually after conversion.
          </p>

          <div className="mt-4 space-y-3">
            {prot.none.includes('Brute Force') && (
              <div className="rounded-md border border-red-100 bg-red-50/50 p-4 dark:border-red-800/30 dark:bg-red-900/10">
                <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">Brute Force</h3>
                <p className="mt-1 text-xs text-red-700 dark:text-red-400">
                  <span className="font-medium">AWAF:</span> Detects login brute-force attacks by tracking failed attempts over a detection window.
                </p>
                <p className="mt-0.5 text-xs text-red-700 dark:text-red-400">
                  <span className="font-medium">XC:</span> Rate limiting is available at the load balancer and service policy levels, but AWAF login-URL-based brute force config cannot be directly mapped.
                </p>
              </div>
            )}

            {prot.none.includes('Session Tracking') && (
              <div className="rounded-md border border-red-100 bg-red-50/50 p-4 dark:border-red-800/30 dark:bg-red-900/10">
                <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">Session Tracking</h3>
                <p className="mt-1 text-xs text-red-700 dark:text-red-400">
                  <span className="font-medium">AWAF:</span> Tracks user sessions to detect anomalies like session hijacking and session awareness.
                </p>
                <p className="mt-0.5 text-xs text-red-700 dark:text-red-400">
                  <span className="font-medium">XC:</span> Client-side JavaScript challenge and fingerprinting exist, but these are configured at the load balancer level — not migrated from the AWAF policy.
                </p>
              </div>
            )}

            {untranslatable.custom_signature_count > 0 && (
              <div className="rounded-md border border-red-100 bg-red-50/50 p-4 dark:border-red-800/30 dark:bg-red-900/10">
                <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">
                  Custom Signatures ({untranslatable.custom_signature_count})
                </h3>
                <p className="mt-1 text-xs text-red-700 dark:text-red-400">
                  Custom AWAF signatures have no equivalent in XC WAF and will be omitted from the conversion.
                </p>
                {untranslatable.custom_signatures.length > 0 && (
                  <table className="mt-2 w-full text-xs">
                    <thead>
                      <tr className="text-left text-gray-500 dark:text-gray-400">
                        <th className="pb-1 pr-4 font-medium">ID</th>
                        <th className="pb-1 pr-4 font-medium">Name</th>
                        <th className="pb-1 font-medium">Scope</th>
                      </tr>
                    </thead>
                    <tbody className="text-gray-700 dark:text-gray-300">
                      {untranslatable.custom_signatures.map((sig) => (
                        <tr key={sig.id}>
                          <td className="py-0.5 pr-4 font-mono">{sig.id}</td>
                          <td className="py-0.5 pr-4">{sig.name}</td>
                          <td className="py-0.5 text-gray-500 dark:text-gray-400">{sig.scope}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </div>

          {warnings.length > 0 && (
            <div className="mt-4 border-t border-red-100 pt-3 dark:border-red-800/30">
              <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Limit Warnings</h3>
              <div className="mt-2 space-y-2">
                {warnings.map((w) => (
                  <div key={w.resource} className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 dark:border-amber-900/50 dark:bg-amber-900/10">
                    <p className="text-xs text-amber-800 dark:text-amber-200">{w.message}</p>
                    <p className="mt-0.5 text-xs text-amber-600 dark:text-amber-400">Current: {w.count} — XC limit: {w.limit}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
