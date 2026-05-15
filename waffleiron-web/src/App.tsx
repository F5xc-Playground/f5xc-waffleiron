import { ConversionProvider, useConversion, type WizardStep } from './context/ConversionContext';
import UploadView from './views/UploadView';
import AnalysisView from './views/AnalysisView';
import ReviewView from './views/ReviewView';
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
                  isCompleted ? 'bg-indigo-500' : 'bg-gray-300 dark:bg-gray-600'
                }`}
              />
            )}
            <button
              type="button"
              onClick={handleClick}
              disabled={!isClickable}
              className={`flex items-center gap-1.5 ${isClickable ? 'cursor-pointer' : 'cursor-default'}`}
            >
              <div
                className={`flex h-7 w-7 items-center justify-center rounded-full text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : isCompleted
                      ? 'bg-indigo-100 text-indigo-700 hover:bg-indigo-200 dark:bg-indigo-900 dark:text-indigo-300 dark:hover:bg-indigo-800'
                      : 'bg-gray-200 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
                }`}
              >
                {isCompleted ? (
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                ) : (
                  i + 1
                )}
              </div>
              <span
                className={`text-sm ${
                  isActive
                    ? 'font-semibold text-gray-900 dark:text-white'
                    : isCompleted
                      ? 'text-gray-700 hover:text-gray-900 dark:text-gray-300 dark:hover:text-white'
                      : 'text-gray-500 dark:text-gray-400'
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
          <div className="mx-auto max-w-4xl rounded-lg border border-dashed border-gray-300 p-12 text-center dark:border-gray-600">
            <p className="text-gray-500 dark:text-gray-400">
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
    <div className="flex min-h-screen flex-col bg-white dark:bg-gray-900">
      <header className="border-b border-gray-200 bg-white px-6 py-4 dark:border-gray-700 dark:bg-gray-900">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src="/assets/waffleiron-dark.jpg"
              alt="WaffleIron"
              className="h-8 w-8 rounded"
            />
            <h1 className="text-xl font-bold tracking-tight text-gray-900 dark:text-white">
              WaffleIron
            </h1>
          </div>
          {state.step !== 'upload' && (
            <button
              onClick={() => dispatch({ type: 'RESET' })}
              className="rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
            >
              Start Over
            </button>
          )}
        </div>
      </header>

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
