import { useState, useCallback } from 'react';
import FileDropzone from '../components/FileDropzone';
import { createConversion, getAnalysis } from '../api';
import { useConversion } from '../context/ConversionContext';

export default function UploadView() {
  const { dispatch } = useConversion();
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileSelected = useCallback(async (file: File) => {
    setError(null);
    setUploading(true);

    try {
      const session = await createConversion(file);
      dispatch({ type: 'UPLOAD_SUCCESS', session });
      const analysis = await getAnalysis(session.id);
      dispatch({ type: 'ANALYSIS_LOADED', analysis });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed. Please try again.');
      setUploading(false);
    }
  }, [dispatch]);

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
            disabled={uploading}
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
              Uploading and analyzing policy...
            </div>
          )}

          {error && (
            <div className="mt-4 rounded-md bg-red-50 px-4 py-3 dark:bg-red-900/20">
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
