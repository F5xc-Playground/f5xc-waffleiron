import { useCallback, useRef, useState } from 'react';
import { Check, Copy, Pencil, RotateCcw, Save, X } from 'lucide-react';
import { validateXCObject } from '../schemas/validate';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

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
        cls = 'text-muted-foreground'; // null
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
    <Card className="gap-0 overflow-hidden rounded-lg py-0">
      {/* Header */}
      <CardHeader className="flex-row items-center justify-between border-b bg-muted/60 px-4 py-2">
        <div className="flex items-center gap-2">
          {title && (
            <CardTitle className="text-sm text-muted-foreground">
              {title}
            </CardTitle>
          )}
          {editing && (
            <Badge variant="outline" className="border-amber-300 bg-amber-100 text-amber-700 dark:border-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
              Editing
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-1">
          {!editing && onSave && (
            <Button
              variant="ghost"
              size="xs"
              onClick={handleEdit}
            >
              <Pencil className="size-3" />
              Edit
            </Button>
          )}
          {editing && (
            <>
              {hasChanges && (
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={handleRevert}
                  className="text-amber-700 hover:bg-amber-100 dark:text-amber-400 dark:hover:bg-amber-900/30"
                >
                  <RotateCcw className="size-3" />
                  Revert
                </Button>
              )}
              <Button
                variant="default"
                size="xs"
                onClick={handleSave}
              >
                <Save className="size-3" />
                Save
              </Button>
              <Button
                variant="ghost"
                size="xs"
                onClick={handleCancel}
              >
                <X className="size-3" />
                Cancel
              </Button>
            </>
          )}
          {!editing && (
            <Button
              variant="ghost"
              size="xs"
              onClick={handleCopy}
            >
              {copied ? (
                <>
                  <Check className="size-3" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="size-3" />
                  Copy
                </>
              )}
            </Button>
          )}
        </div>
      </CardHeader>

      {/* Errors */}
      {(parseError || validationErrors.length > 0) && (
        <div className="border-b border-destructive/30 bg-destructive/10 px-4 py-2">
          {parseError && (
            <p className="text-xs font-medium text-destructive">
              JSON Error: {parseError}
            </p>
          )}
          {validationErrors.length > 0 && (
            <div className="space-y-0.5">
              <p className="text-xs font-medium text-destructive">
                Schema validation errors:
              </p>
              {validationErrors.map((err, i) => (
                <p key={i} className="pl-2 text-xs text-destructive/80">
                  {err}
                </p>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Content */}
      <CardContent className="p-0">
        {editing ? (
          <div className="overflow-x-auto bg-background">
            <div className="flex">
              <div
                aria-hidden="true"
                className="shrink-0 select-none border-r border-border bg-muted/40 px-3 py-3 text-right font-mono text-xs leading-5 text-muted-foreground/60"
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
                className="flex-1 resize-y border-0 bg-transparent p-3 font-mono text-xs leading-5 text-foreground focus:outline-none focus:ring-0"
                style={{ minHeight: `${Math.max(editValue.split('\n').length, 10) * 20 + 24}px` }}
              />
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto bg-background">
            <div className="flex">
              <div
                aria-hidden="true"
                className="shrink-0 select-none border-r border-border bg-muted/40 px-3 py-3 text-right font-mono text-xs leading-5 text-muted-foreground/60"
              >
                {lines.map((_, i) => (
                  <div key={i}>{i + 1}</div>
                ))}
              </div>
              <pre
                ref={preRef}
                className="flex-1 overflow-x-auto p-3 font-mono text-xs leading-5 text-foreground"
                dangerouslySetInnerHTML={{ __html: highlighted }}
              />
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
