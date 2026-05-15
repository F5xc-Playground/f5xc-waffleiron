import { useEffect, useState } from 'react';
import { getReport } from '../api';

interface GapReportProps {
  sessionId: string;
}

export default function GapReport({ sessionId }: GapReportProps) {
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchReport() {
      setLoading(true);
      setError(null);
      try {
        const markdown = await getReport(sessionId, 'markdown');
        if (!cancelled) setReport(markdown);
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

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-5 py-8 dark:border-gray-700 dark:bg-gray-800">
        <svg className="h-4 w-4 animate-spin text-gray-400" viewBox="0 0 24 24" fill="none">
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
          />
        </svg>
        <span className="text-sm text-gray-500 dark:text-gray-400">
          Loading gap report...
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 px-5 py-4 dark:border-red-900 dark:bg-red-900/20">
        <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="border-b border-gray-200 bg-gray-50 px-4 py-2 dark:border-gray-700 dark:bg-gray-800/60">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
          Gap Report
        </h3>
      </div>
      <div className="overflow-x-auto bg-white dark:bg-gray-900">
        <pre className="whitespace-pre-wrap p-4 font-mono text-xs leading-relaxed text-gray-700 dark:text-gray-300">
          {report}
        </pre>
      </div>
    </div>
  );
}
