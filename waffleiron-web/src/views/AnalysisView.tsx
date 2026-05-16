import { useState, useCallback, useRef } from 'react';
import SummaryCards from '../components/SummaryCards';
import DecisionsTable from '../components/DecisionsTable';
import { submitDecisions } from '../api';
import { useConversion } from '../context/ConversionContext';
import type { DecisionRequest, PolicyOverrides } from '../types';

export default function AnalysisView() {
  const { state, dispatch } = useConversion();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const decisionsRef = useRef<DecisionRequest>({
    alarm_only_signatures: [],
  });

  const analysis = state.analysis;
  const sessionId = state.sessionId;

  const handleDecisionsChange = useCallback((decisions: DecisionRequest) => {
    decisionsRef.current = decisions;
  }, []);

  const handleOverridesChange = useCallback((overrides: PolicyOverrides) => {
    dispatch({ type: 'SET_OVERRIDES', overrides });
  }, [dispatch]);

  const handleContinue = useCallback(async () => {
    if (!sessionId) return;

    setError(null);
    setSubmitting(true);

    try {
      await submitDecisions(sessionId, decisionsRef.current);
      dispatch({ type: 'GO_TO_STEP', step: 'review' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit decisions.');
      setSubmitting(false);
    }
  }, [sessionId, dispatch]);

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
        <SummaryCards
          summary={analysis.summary}
          policyInfo={analysis.policy_info}
          overrides={state.overrides}
          onOverridesChange={handleOverridesChange}
          botGaps={analysis.bot_gaps}
          blockingPageGaps={analysis.blocking_page_gaps ?? []}
          ipIntelGaps={analysis.ip_intel_gaps ?? []}
          untranslatable={analysis.untranslatable}
          warnings={analysis.warnings}
        />

        <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
            Alarm-Only Overrides
          </h2>
          <DecisionsTable
            signatures={analysis.alarm_only_signatures}
            violations={analysis.alarm_only_violations}
            onDecisionsChange={handleDecisionsChange}
          />
        </div>

        {/* Continue to Export */}
        <div className="flex items-center justify-end gap-4">
          {error && (
            <div className="rounded-md bg-red-50 px-4 py-3 dark:bg-red-900/20">
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
            </div>
          )}
          <button
            type="button"
            onClick={handleContinue}
            disabled={submitting}
            className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? 'Submitting...' : 'Export'}
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  );
}
