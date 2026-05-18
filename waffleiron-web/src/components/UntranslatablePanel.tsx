import type { UntranslatableSummary } from '../types';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';

interface UntranslatablePanelProps {
  untranslatable: UntranslatableSummary;
}

export default function UntranslatablePanel({ untranslatable }: UntranslatablePanelProps) {
  if (untranslatable.custom_signatures.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">
          Custom Signatures
        </CardTitle>
        <CardDescription>
          These custom AWAF signatures have no equivalent in XC WAF and will be omitted from the conversion.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-hidden rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs uppercase">ID</TableHead>
                <TableHead className="text-xs uppercase">Name</TableHead>
                <TableHead className="text-xs uppercase">Scope</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {untranslatable.custom_signatures.map((sig) => (
                <TableRow key={sig.id}>
                  <TableCell className="font-mono text-xs">{sig.id}</TableCell>
                  <TableCell>{sig.name}</TableCell>
                  <TableCell className="text-muted-foreground">{sig.scope}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
