import { ConversionProvider, useConversion, type WizardStep } from './context/ConversionContext';
import UploadView from './views/UploadView';
import AnalysisView from './views/AnalysisView';
import ReviewView from './views/ReviewView';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Check, RotateCcw } from 'lucide-react';

const STEPS: { key: WizardStep; label: string }[] = [
  { key: 'upload', label: 'Upload' },
  { key: 'analysis', label: 'Analysis' },
  { key: 'review', label: 'Export' },
];

function WizardSteps() {
  const { state, dispatch } = useConversion();
  const currentIndex = STEPS.findIndex((s) => s.key === state.step);

  return (
    <nav className="flex items-center justify-center gap-2 py-6">
      {STEPS.map((step, i) => {
        const isActive = step.key === state.step;
        const isCompleted = i < currentIndex;
        const isClickable = isCompleted;

        const handleClick = () => {
          if (isClickable) {
            dispatch({ type: 'GO_TO_STEP', step: step.key });
          }
        };

        return (
          <div key={step.key} className="flex items-center gap-2">
            {i > 0 && (
              <div
                className={`h-px w-8 ${
                  isCompleted ? 'bg-primary' : 'bg-border'
                }`}
              />
            )}
            <button
              type="button"
              onClick={handleClick}
              disabled={!isClickable}
              className={`flex items-center gap-1.5 ${isClickable ? 'cursor-pointer' : 'cursor-default'}`}
            >
              <Badge
                variant={isActive ? 'default' : isCompleted ? 'secondary' : 'outline'}
                className={`flex h-7 w-7 items-center justify-center rounded-full text-sm font-semibold transition-colors ${
                  isCompleted ? 'hover:bg-secondary/80' : ''
                }`}
              >
                {isCompleted ? (
                  <Check className="size-3.5" strokeWidth={2.5} />
                ) : (
                  i + 1
                )}
              </Badge>
              <span
                className={`text-sm ${
                  isActive
                    ? 'font-semibold text-foreground'
                    : isCompleted
                      ? 'text-muted-foreground hover:text-foreground'
                      : 'text-muted-foreground/60'
                }`}
              >
                {step.label}
              </span>
            </button>
          </div>
        );
      })}
    </nav>
  );
}

function CurrentView() {
  const { state } = useConversion();

  switch (state.step) {
    case 'upload':
      return <UploadView />;
    case 'analysis':
      return <AnalysisView />;
    case 'review':
      return <ReviewView />;
    default:
      return (
        <div className="flex-1 px-6 py-4">
          <div className="mx-auto max-w-4xl rounded-lg border border-dashed border-border p-12 text-center">
            <p className="text-muted-foreground">
              Step: <span className="font-semibold capitalize">{state.step}</span>
              {' '} — view not yet implemented
            </p>
          </div>
        </div>
      );
  }
}

function AppContent() {
  const { state, dispatch } = useConversion();

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="bg-background px-6 py-4">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src="/assets/waffleiron-dark.jpg"
              alt="WaffleIron"
              className="h-8 w-8 rounded"
            />
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              WaffleIron
            </h1>
          </div>
          {state.step !== 'upload' && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => dispatch({ type: 'RESET' })}
            >
              <RotateCcw className="size-3.5" />
              Start Over
            </Button>
          )}
        </div>
      </header>
      <Separator />

      <div className="mx-auto w-full max-w-5xl">
        <WizardSteps />
        <CurrentView />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ConversionProvider>
      <AppContent />
    </ConversionProvider>
  );
}
