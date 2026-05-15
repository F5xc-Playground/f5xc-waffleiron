import { useState, useCallback, useRef } from 'react';
import SummaryCards from '../components/SummaryCards';
import DecisionsTable from '../components/DecisionsTable';
import { submitDecisions, runTranslation } from '../api';
import { useConversion } from '../context/ConversionContext';
import type { DecisionRequest } from '../types';

export default function AnalysisView() {
  const { state, dispatch } = useConversion();
  const [namespace, setNamespace] = useState('');
  const [translating, setTranslating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const decisionsRef = useRef<DecisionRequest>({
    alarm_only_signatures: [],
  });

  const analysis = state.analysis;
  const sessionId = state.sessionId;

  const handleDecisionsChange = useCallback((decisions: DecisionRequest) => {
    decisionsRef.current = decisions;
  }, []);

  const deferredCount = (() => {
    const d = decisionsRef.current;
    const sigDeferred = d.alarm_only_signatures.filter((s) => s.action === 'defer').length;
    const violDeferred = d.alarm_only_violations?.filter((v) => v.action === 'defer').length ?? 0;
    return sigDeferred + violDeferred;
  })();

  const handleTranslate = useCallback(async () => {
    if (!sessionId) return;

    setError(null);
    setTranslating(true);

    try {
      await submitDecisions(sessionId, decisionsRef.current);
      const outputs = await runTranslation(sessionId, namespace);
      dispatch({ type: 'TRANSLATION_COMPLETE', outputs });
      dispatch({ type: 'GO_TO_STEP', step: 'review' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Translation failed. Please try again.');
      setTranslating(false);
    }
  }, [sessionId, namespace, dispatch]);

  if (!analysis) {
    return (
      <div className="flex-1 px-6 py-4">
        <div className="mx-auto max-w-4xl rounded-lg border border-dashed border-gray-300 p-12 text-center dark:border-gray-600">
          <p className="text-gray-500 dark:text-gray-400">No analysis data available.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 px-6 py-4">
      <div className="mx-auto max-w-5xl space-y-6">
        {/* Summary */}
        <SummaryCards summary={analysis.summary} />

        {/* Decisions table */}
        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
            Alarm-Only Decisions
          </h2>
          <DecisionsTable
            signatures={analysis.alarm_only_signatures}
            violations={analysis.alarm_only_violations}
            onDecisionsChange={handleDecisionsChange}
          />
        </div>

        {/* Namespace + Translate */}
        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <label
            htmlFor="namespace"
            className="mb-1 block text-sm font-medium text-gray-700 dark:text-gray-300"
          >
            Target Namespace
          </label>
          <input
            id="namespace"
            type="text"
            placeholder="e.g. my-namespace"
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
            className="mb-4 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm placeholder:text-gray-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900 dark:text-white dark:placeholder:text-gray-500"
          />

          {error && (
            <div className="mb-4 rounded-md bg-red-50 px-4 py-3 dark:bg-red-900/20">
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
            </div>
          )}

          <button
            type="button"
            onClick={handleTranslate}
            disabled={translating}
            className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {translating ? (
              <>
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
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
                Translating...
              </>
            ) : (
              <>
                Translate
                {deferredCount > 0 && (
                  <span className="rounded-full bg-indigo-500 px-2 py-0.5 text-xs">
                    {deferredCount} deferred
                  </span>
                )}
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
