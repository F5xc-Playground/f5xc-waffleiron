import type {
  ConversionSession,
  AnalysisResult,
  DecisionRequest,
  TranslationOutputs,
  PushRequest,
  PushResult,
  XCStatus,
} from './types';

const BASE = '/api/v1';

export async function createConversion(file: File): Promise<ConversionSession> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${BASE}/conversions`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getAnalysis(id: string): Promise<AnalysisResult> {
  const res = await fetch(`${BASE}/conversions/${id}/analysis`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function submitDecisions(id: string, decisions: DecisionRequest): Promise<void> {
  const res = await fetch(`${BASE}/conversions/${id}/decisions`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(decisions),
  });
  if (!res.ok) throw new Error(await res.text());
}

export async function runTranslation(id: string, namespace: string): Promise<TranslationOutputs> {
  const res = await fetch(`${BASE}/conversions/${id}/translate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ namespace }),
  });
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  return data.outputs;
}

export async function getOutput(id: string, type: string): Promise<object> {
  const res = await fetch(`${BASE}/conversions/${id}/outputs/${type}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getReport(id: string, format: 'json' | 'markdown'): Promise<string> {
  const accept = format === 'json' ? 'application/json' : 'text/markdown';
  const res = await fetch(`${BASE}/conversions/${id}/report`, { headers: { Accept: accept } });
  if (!res.ok) throw new Error(await res.text());
  return format === 'json' ? res.json() : res.text();
}

export async function pushToXC(id: string, request: PushRequest): Promise<PushResult[]> {
  const res = await fetch(`${BASE}/conversions/${id}/push`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  return data.results;
}

export async function getXCStatus(): Promise<XCStatus> {
  const res = await fetch(`${BASE}/xc/status`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function listNamespaces(tenantUrl?: string, apiToken?: string): Promise<string[]> {
  const params = new URLSearchParams();
  if (tenantUrl) params.set('tenant_url', tenantUrl);
  if (apiToken) params.set('api_token', apiToken);
  const res = await fetch(`${BASE}/xc/namespaces?${params}`);
  if (!res.ok) throw new Error(await res.text());
  const data = await res.json();
  return data.namespaces;
}

export async function deleteConversion(id: string): Promise<void> {
  const res = await fetch(`${BASE}/conversions/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(await res.text());
}
