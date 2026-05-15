import { useState, useCallback } from 'react';
import FileDropzone from '../components/FileDropzone';
import { createConversion, getAnalysis } from '../api';
import { useConversion } from '../context/ConversionContext';
import type { ConversionSession } from '../types';

export default function UploadView() {
  const { dispatch } = useConversion();
  const [session, setSession] = useState<ConversionSession | null>(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileSelected = useCallback(async (file: File) => {
    setError(null);
    setSession(null);
    setUploading(true);

    try {
      const result = await createConversion(file);
      setSession(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed. Please try again.');
    } finally {
      setUploading(false);
    }
  }, []);

  const handleAnalyze = useCallback(async () => {
    if (!session) return;

    setError(null);
    setAnalyzing(true);

    try {
      dispatch({ type: 'UPLOAD_SUCCESS', session });
      const analysis = await getAnalysis(session.id);
      dispatch({ type: 'ANALYSIS_LOADED', analysis });
      dispatch({ type: 'GO_TO_STEP', step: 'analysis' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
      setAnalyzing(false);
    }
  }, [session, dispatch]);

  return (
    <div className="flex-1 px-6 py-4">
      <div className="mx-auto max-w-2xl">
        <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <h2 className="mb-1 text-lg font-semibold text-gray-900 dark:text-white">
            Upload ASM Policy
          </h2>
          <p className="mb-5 text-sm text-gray-500 dark:text-gray-400">
            Upload a BIG-IP ASM policy export file to begin conversion.
          </p>

          <FileDropzone
            onFileSelected={handleFileSelected}
            disabled={uploading || analyzing}
          />

          {uploading && (
            <div className="mt-4 flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
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
              Uploading and parsing policy...
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-md bg-red-50 px-4 py-3 dark:bg-red-900/20">
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
            </div>
          )}

          {session && !uploading && (
            <div className="mt-5 space-y-4">
              <div className="rounded-md bg-gray-50 px-4 py-3 dark:bg-gray-700/50">
                <h3 className="mb-2 text-sm font-medium text-gray-700 dark:text-gray-300">
                  Policy Summary
                </h3>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                  <dt className="text-gray-500 dark:text-gray-400">Name</dt>
                  <dd className="font-medium text-gray-900 dark:text-white">
                    {session.policy_name}
                  </dd>
                  <dt className="text-gray-500 dark:text-gray-400">Status</dt>
                  <dd className="font-medium text-gray-900 dark:text-white capitalize">
                    {session.status}
                  </dd>
                </dl>
              </div>

              <button
                type="button"
                onClick={handleAnalyze}
                disabled={analyzing}
                className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {analyzing ? (
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
                    Analyzing...
                  </>
                ) : (
                  'Analyze Policy'
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
