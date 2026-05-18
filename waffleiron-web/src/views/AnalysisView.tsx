import { useState, useCallback, useRef } from 'react';
import { ChevronRight } from 'lucide-react';
import SummaryCards from '../components/SummaryCards';
import DecisionsTable from '../components/DecisionsTable';
import { submitDecisions } from '../api';
import { useConversion } from '../context/ConversionContext';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
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
        <div className="mx-auto max-w-4xl rounded-lg border border-dashed border-border p-12 text-center">
          <p className="text-muted-foreground">No analysis data available.</p>
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

        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Alarm-Only Overrides</CardTitle>
          </CardHeader>
          <CardContent>
            <DecisionsTable
              signatures={analysis.alarm_only_signatures}
              violations={analysis.alarm_only_violations}
              onDecisionsChange={handleDecisionsChange}
            />
          </CardContent>
        </Card>

        {/* Continue to Export */}
        <div className="flex items-center justify-end gap-4">
          {error && (
            <Alert variant="destructive" className="flex-1">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <Button
            onClick={handleContinue}
            disabled={submitting}
          >
            {submitting ? 'Submitting...' : 'Export'}
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
