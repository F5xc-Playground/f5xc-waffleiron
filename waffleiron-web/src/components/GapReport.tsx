import { useEffect, useState, useCallback, useMemo } from 'react';
import { marked } from 'marked';
import { Download, Loader2 } from 'lucide-react';
import { getReport } from '../api';
import { Card, CardHeader, CardTitle, CardAction, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface GapReportProps {
  sessionId: string;
}

export default function GapReport({ sessionId }: GapReportProps) {
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchReport() {
      setLoading(true);
      setError(null);
      try {
        const markdown = await getReport(sessionId, 'markdown');
        if (!cancelled) setReport(markdown);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : 'Failed to load gap report',
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchReport();
    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  const renderedHtml = useMemo(() => {
    if (!report) return '';
    return marked.parse(report, { async: false }) as string;
  }, [report]);

  const handleDownload = useCallback(() => {
    if (!report) return;
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gap_report-${sessionId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [report, sessionId]);

  if (loading) {
    return (
      <Card className="px-5 py-8">
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          <span className="text-sm text-muted-foreground">
            Loading gap report...
          </span>
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="border-destructive bg-destructive/10 px-5 py-4">
        <p className="text-sm text-destructive">{error}</p>
      </Card>
    );
  }

  return (
    <Card className="gap-0 overflow-hidden py-0">
      <CardHeader className="border-b py-2">
        <CardTitle className="text-sm">
          Gap Report
        </CardTitle>
        <CardAction>
          <Button
            type="button"
            variant="ghost"
            size="xs"
            onClick={handleDownload}
          >
            <Download className="h-3.5 w-3.5" />
            Download
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="py-4">
        <div
          className="prose prose-sm max-w-none dark:prose-invert prose-headings:text-foreground prose-p:text-muted-foreground prose-strong:text-foreground prose-li:text-muted-foreground"
          dangerouslySetInnerHTML={{ __html: renderedHtml }}
        />
      </CardContent>
    </Card>
  );
}
