import { useCallback, useRef, useState } from 'react';
import { validateXCObject } from '../schemas/validate';

interface JsonViewerProps {
  data: object;
  title?: string;
  objectType?: string;
  onSave?: (updated: object) => void;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function syntaxHighlight(json: string): string {
  const escaped = escapeHtml(json);
  return escaped.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = 'text-amber-600 dark:text-amber-400'; // number
      if (/^"/.test(match)) {
        cls = /:$/.test(match)
          ? 'text-blue-700 dark:text-blue-400' // key
          : 'text-emerald-600 dark:text-emerald-400'; // string
      } else if (/true|false/.test(match)) {
        cls = 'text-purple-600 dark:text-purple-400'; // boolean
      } else if (/null/.test(match)) {
        cls = 'text-gray-400 dark:text-gray-500'; // null
      }
      return `<span class="${cls}">${match}</span>`;
    },
  );
}

export default function JsonViewer({ data, title, objectType, onSave }: JsonViewerProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editValue, setEditValue] = useState('');
  const [originalValue, setOriginalValue] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  const raw = JSON.stringify(data, null, 2);
  const lines = raw.split('\n');
  const highlighted = syntaxHighlight(raw);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(raw);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      if (preRef.current) {
        const range = document.createRange();
        range.selectNodeContents(preRef.current);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
    }
  }, [raw]);

  const handleEdit = useCallback(() => {
    setEditValue(raw);
    setOriginalValue(raw);
    setParseError(null);
    setValidationErrors([]);
    setEditing(true);
  }, [raw]);

  const handleCancel = useCallback(() => {
    setEditing(false);
    setParseError(null);
    setValidationErrors([]);
  }, []);

  const handleRevert = useCallback(() => {
    setEditValue(originalValue);
    setParseError(null);
    setValidationErrors([]);
  }, [originalValue]);

  const handleSave = useCallback(() => {
    let parsed: object;
    try {
      parsed = JSON.parse(editValue);
    } catch (e) {
      setParseError(e instanceof Error ? e.message : 'Invalid JSON');
      return;
    }
    setParseError(null);

    if (objectType) {
      const result = validateXCObject(objectType, parsed);
      if (!result.valid) {
        setValidationErrors(result.errors);
        return;
      }
    }

    setValidationErrors([]);
    setEditing(false);
    onSave?.(parsed);
  }, [editValue, objectType, onSave]);

  const hasChanges = editing && editValue !== originalValue;

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-gray-200 bg-gray-50 px-4 py-2 dark:border-gray-700 dark:bg-gray-800/60">
        <div className="flex items-center gap-2">
          {title && (
            <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
              {title}
            </h3>
          )}
          {editing && (
            <span className="rounded bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
              Editing
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {!editing && onSave && (
            <button
              type="button"
              onClick={handleEdit}
              className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-700"
            >
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
              </svg>
              Edit
            </button>
          )}
          {editing && (
            <>
              {hasChanges && (
                <button
                  type="button"
                  onClick={handleRevert}
                  className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-amber-700 transition-colors hover:bg-amber-100 dark:text-amber-400 dark:hover:bg-amber-900/30"
                >
                  Revert
                </button>
              )}
              <button
                type="button"
                onClick={handleSave}
                className="inline-flex items-center gap-1.5 rounded-md bg-indigo-100 px-2.5 py-1 text-xs font-medium text-indigo-700 transition-colors hover:bg-indigo-200 dark:bg-indigo-900/30 dark:text-indigo-400 dark:hover:bg-indigo-900/50"
              >
                Save
              </button>
              <button
                type="button"
                onClick={handleCancel}
                className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            </>
          )}
          {!editing && (
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-200 dark:text-gray-400 dark:hover:bg-gray-700"
            >
              {copied ? (
                <>
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                  Copied
                </>
              ) : (
                <>
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  Copy
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Errors */}
      {(parseError || validationErrors.length > 0) && (
        <div className="border-b border-red-200 bg-red-50 px-4 py-2 dark:border-red-800 dark:bg-red-900/20">
          {parseError && (
            <p className="text-xs font-medium text-red-700 dark:text-red-400">
              JSON Error: {parseError}
            </p>
          )}
          {validationErrors.length > 0 && (
            <div className="space-y-0.5">
              <p className="text-xs font-medium text-red-700 dark:text-red-400">
                Schema validation errors:
              </p>
              {validationErrors.map((err, i) => (
                <p key={i} className="pl-2 text-xs text-red-600 dark:text-red-400">
                  {err}
                </p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Content */}
      {editing ? (
        <div className="overflow-x-auto bg-white dark:bg-gray-900">
          <div className="flex">
            <div
              aria-hidden="true"
              className="shrink-0 select-none border-r border-gray-200 bg-gray-50 px-3 py-3 text-right font-mono text-xs leading-5 text-gray-400 dark:border-gray-700 dark:bg-gray-800/40 dark:text-gray-600"
            >
              {editValue.split('\n').map((_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <textarea
              value={editValue}
              onChange={(e) => {
                setEditValue(e.target.value);
                setParseError(null);
                setValidationErrors([]);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Tab') {
                  e.preventDefault();
                  const ta = e.currentTarget;
                  const start = ta.selectionStart;
                  const end = ta.selectionEnd;
                  const updated = editValue.substring(0, start) + '  ' + editValue.substring(end);
                  setEditValue(updated);
                  requestAnimationFrame(() => {
                    ta.selectionStart = ta.selectionEnd = start + 2;
                  });
                }
              }}
              spellCheck={false}
              className="flex-1 resize-y border-0 bg-transparent p-3 font-mono text-xs leading-5 text-gray-800 focus:outline-none focus:ring-0 dark:text-gray-200"
              style={{ minHeight: `${Math.max(editValue.split('\n').length, 10) * 20 + 24}px` }}
            />
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto bg-white dark:bg-gray-900">
          <div className="flex">
            <div
              aria-hidden="true"
              className="shrink-0 select-none border-r border-gray-200 bg-gray-50 px-3 py-3 text-right font-mono text-xs leading-5 text-gray-400 dark:border-gray-700 dark:bg-gray-800/40 dark:text-gray-600"
            >
              {lines.map((_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <pre
              ref={preRef}
              className="flex-1 overflow-x-auto p-3 font-mono text-xs leading-5 text-gray-800 dark:text-gray-200"
              dangerouslySetInnerHTML={{ __html: highlighted }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
