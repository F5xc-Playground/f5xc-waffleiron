import { useState, useRef, useCallback, type DragEvent } from 'react';

interface FileDropzoneProps {
  onFileSelected: (file: File) => void;
  disabled?: boolean;
}

const ACCEPTED_EXTENSIONS = ['.xml', '.json'];
const ACCEPTED_MIME_TYPES = ['application/xml', 'text/xml', 'application/json'];

function isAcceptedFile(file: File): boolean {
  const name = file.name.toLowerCase();
  return (
    ACCEPTED_EXTENSIONS.some((ext) => name.endsWith(ext)) ||
    ACCEPTED_MIME_TYPES.includes(file.type)
  );
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function FileDropzone({ onFileSelected, disabled = false }: FileDropzoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    (file: File) => {
      setError(null);
      if (!isAcceptedFile(file)) {
        setError('Invalid file type. Please upload an .xml or .json file.');
        return;
      }
      setSelectedFile(file);
      onFileSelected(file);
    },
    [onFileSelected],
  );

  const handleDragOver = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      if (!disabled) setIsDragging(true);
    },
    [disabled],
  );

  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      if (disabled) return;

      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [disabled, handleFile],
  );

  const handleClick = useCallback(() => {
    if (!disabled) inputRef.current?.click();
  }, [disabled]);

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleClick}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') handleClick();
        }}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-10 transition-colors ${
          disabled
            ? 'cursor-not-allowed border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-800/50'
            : isDragging
              ? 'border-indigo-500 bg-indigo-50 dark:border-indigo-400 dark:bg-indigo-950/30'
              : 'border-gray-300 bg-white hover:border-gray-400 dark:border-gray-600 dark:bg-gray-800 dark:hover:border-gray-500'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".xml,.json"
          onChange={handleInputChange}
          className="hidden"
        />

        {/* Upload icon */}
        <svg
          className={`mb-3 h-10 w-10 ${
            isDragging
              ? 'text-indigo-500 dark:text-indigo-400'
              : 'text-gray-400 dark:text-gray-500'
          }`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"
          />
        </svg>

        <p className="mb-1 text-sm font-medium text-gray-700 dark:text-gray-300">
          {isDragging ? 'Drop file here' : 'Drag and drop your AWAF policy file'}
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          or click to browse (.xml, .json)
        </p>
      </div>

      {selectedFile && (
        <div className="mt-3 flex items-center gap-2 rounded-md bg-gray-50 px-3 py-2 dark:bg-gray-800">
          <svg
            className="h-4 w-4 shrink-0 text-gray-500 dark:text-gray-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"
            />
          </svg>
          <span className="truncate text-sm text-gray-700 dark:text-gray-300">
            {selectedFile.name}
          </span>
          <span className="ml-auto shrink-0 text-xs text-gray-500 dark:text-gray-400">
            {formatFileSize(selectedFile.size)}
          </span>
        </div>
      )}

      {error && (
        <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>
      )}
    </div>
  );
}
