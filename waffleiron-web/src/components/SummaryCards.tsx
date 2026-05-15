import type { ConversionSummary } from '../types';

interface SummaryCardsProps {
  summary: ConversionSummary;
}

const cards = [
  { key: 'total', label: 'Total Features', color: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200' },
  { key: 'directly_translated', label: 'Directly Translated', color: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300' },
  { key: 'translated_with_loss', label: 'Translated with Loss', color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300' },
  { key: 'decisions_required', label: 'Decisions Required', color: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300' },
  { key: 'cannot_translate', label: 'Cannot Translate', color: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300' },
] as const;

export default function SummaryCards({ summary }: SummaryCardsProps) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {cards.map((card) => (
        <div
          key={card.key}
          className={`rounded-lg px-4 py-3 ${card.color}`}
        >
          <p className="text-2xl font-bold">{summary[card.key]}</p>
          <p className="text-xs font-medium opacity-80">{card.label}</p>
        </div>
      ))}
    </div>
  );
}
