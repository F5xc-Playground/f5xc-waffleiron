import type { UntranslatableSummary } from '../types';

interface UntranslatablePanelProps {
  untranslatable: UntranslatableSummary;
}

export default function UntranslatablePanel({ untranslatable }: UntranslatablePanelProps) {
  if (untranslatable.custom_signatures.length === 0) return null;

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
      <h2 className="mb-1 text-lg font-semibold text-gray-900 dark:text-white">
        Custom Signatures
      </h2>
      <p className="mb-4 text-sm text-gray-500 dark:text-gray-400">
        These custom AWAF signatures have no equivalent in XC WAF and will be omitted from the conversion.
      </p>
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
  );
}
