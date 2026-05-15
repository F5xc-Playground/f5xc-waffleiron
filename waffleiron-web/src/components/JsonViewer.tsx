import { useCallback, useRef, useState } from 'react';

interface JsonViewerProps {
  data: object;
  title?: string;
}

function syntaxHighlight(json: string): string {
  return json.replace(
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

export default function JsonViewer({ data, title }: JsonViewerProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState(false);

  const raw = JSON.stringify(data, null, 2);
  const lines = raw.split('\n');
  const highlighted = syntaxHighlight(raw);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(raw);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback: select text in the pre element
      if (preRef.current) {
        const range = document.createRange();
        range.selectNodeContents(preRef.current);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
    }
  }, [raw]);

  return (
    <div className="overflow-hidden rounded-lg border border-gray-200 dark:border-gray-700">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-gray-200 bg-gray-50 px-4 py-2 dark:border-gray-700 dark:bg-gray-800/60">
        {title && (
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
            {title}
          </h3>
        )}
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
              Copy JSON
            </>
          )}
        </button>
      </div>

      {/* Code block with line numbers */}
      <div className="overflow-x-auto bg-white dark:bg-gray-900">
        <div className="flex">
          {/* Line numbers gutter */}
          <div
            aria-hidden="true"
            className="shrink-0 select-none border-r border-gray-200 bg-gray-50 px-3 py-3 text-right font-mono text-xs leading-5 text-gray-400 dark:border-gray-700 dark:bg-gray-800/40 dark:text-gray-600"
          >
            {lines.map((_, i) => (
              <div key={i}>{i + 1}</div>
            ))}
          </div>

          {/* Highlighted JSON */}
          <pre
            ref={preRef}
            className="flex-1 overflow-x-auto p-3 font-mono text-xs leading-5 text-gray-800 dark:text-gray-200"
            dangerouslySetInnerHTML={{ __html: highlighted }}
          />
        </div>
      </div>
    </div>
  );
}
