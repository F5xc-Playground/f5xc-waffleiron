import { ConversionProvider, useConversion, type WizardStep } from './context/ConversionContext';
import UploadView from './views/UploadView';
import AnalysisView from './views/AnalysisView';
import ReviewView from './views/ReviewView';
import PushView from './views/PushView';

const STEPS: { key: WizardStep; label: string }[] = [
  { key: 'upload', label: 'Upload' },
  { key: 'analysis', label: 'Analysis' },
  { key: 'review', label: 'Review' },
  { key: 'push', label: 'Push' },
];

function WizardSteps() {
  const { state } = useConversion();
  const currentIndex = STEPS.findIndex((s) => s.key === state.step);

  return (
    <nav className="flex items-center justify-center gap-2 py-6">
      {STEPS.map((step, i) => {
        const isActive = step.key === state.step;
        const isCompleted = i < currentIndex;

        return (
          <div key={step.key} className="flex items-center gap-2">
            {i > 0 && (
              <div
                className={`h-px w-8 ${
                  isCompleted ? 'bg-indigo-500' : 'bg-gray-300 dark:bg-gray-600'
                }`}
              />
            )}
            <div className="flex items-center gap-1.5">
              <div
                className={`flex h-7 w-7 items-center justify-center rounded-full text-sm font-medium ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : isCompleted
                      ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300'
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
                    : 'text-gray-500 dark:text-gray-400'
                }`}
              >
                {step.label}
              </span>
            </div>
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
    case 'push':
      return <PushView />;
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
  return (
    <div className="flex min-h-screen flex-col bg-white dark:bg-gray-900">
      <header className="border-b border-gray-200 bg-white px-6 py-4 dark:border-gray-700 dark:bg-gray-900">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-gray-900 dark:text-white">
              WaffleIron
            </h1>
            <span className="rounded-full bg-indigo-100 px-2.5 py-0.5 text-xs font-medium text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">
              ASM to XC
            </span>
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            WAF Policy Converter
          </p>
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
