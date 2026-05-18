import { useState, useCallback } from 'react';
import { Loader2 } from 'lucide-react';
import FileDropzone from '../components/FileDropzone';
import { createConversion, getAnalysis } from '../api';
import { useConversion } from '../context/ConversionContext';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';

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
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Upload AWAF Policy</CardTitle>
            <CardDescription>
              Upload a BIG-IP AWAF policy export file to begin conversion.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FileDropzone
              onFileSelected={handleFileSelected}
              disabled={uploading}
            />

            {uploading && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Uploading and analyzing policy...
              </div>
            )}

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
