import { useState, useRef, useCallback, type DragEvent } from 'react';
import { Upload, FileText, AlertCircle } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

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
            ? 'cursor-not-allowed border-border bg-muted/50 text-muted-foreground'
            : isDragging
              ? 'border-primary bg-primary/5'
              : 'border-border bg-card hover:border-primary/50'
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
        <Upload
          className={`mb-3 size-10 ${
            isDragging
              ? 'text-primary'
              : 'text-muted-foreground'
          }`}
          strokeWidth={1.5}
        />

        <p className="mb-1 text-sm font-medium text-card-foreground">
          {isDragging ? 'Drop file here' : 'Drag and drop your AWAF policy file'}
        </p>
        <p className="text-xs text-muted-foreground">
          or click to browse (.xml, .json)
        </p>
      </div>

      {selectedFile && (
        <div className="mt-3 flex items-center gap-2 rounded-md bg-muted px-3 py-2">
          <FileText
            className="size-4 shrink-0 text-muted-foreground"
            strokeWidth={1.5}
          />
          <span className="truncate text-sm text-card-foreground">
            {selectedFile.name}
          </span>
          <span className="ml-auto shrink-0 text-xs text-muted-foreground">
            {formatFileSize(selectedFile.size)}
          </span>
        </div>
      )}

      {error && (
        <Alert variant="destructive" className="mt-2">
          <AlertCircle />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
