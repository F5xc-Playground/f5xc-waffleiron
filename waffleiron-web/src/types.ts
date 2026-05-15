export interface ConversionSession {
  id: string;
  status: 'parsed' | 'analyzed' | 'translated';
  policy_name: string;
}

export interface AnalysisResult {
  summary: ConversionSummary;
  alarm_only_signatures: AlarmOnlySignature[];
  alarm_only_violations: AlarmOnlyViolation[];
}

export interface ConversionSummary {
  total: number;
  directly_translated: number;
  translated_with_loss: number;
  decisions_required: number;
  cannot_translate: number;
}

export interface AlarmOnlySignature {
  sig_id: number;
  description: string;
  scope: string;
  action: 'exclude' | 'enforce' | 'defer';
}

export interface AlarmOnlyViolation {
  violation_name: string;
  action: 'disable' | 'enforce' | 'defer';
}

export interface TranslationOutputs {
  app_firewall?: object;
  exclusion_policy?: object;
  service_policy?: object;
  http_lb_patch?: object;
}

export interface PushResult {
  object_type: string;
  success: boolean;
  error?: string;
}

export interface XCStatus {
  configured: boolean;
  connected?: boolean;
  tenant_url?: string;
}

export interface DecisionRequest {
  alarm_only_signatures: Array<{ sig_id: number; action: string }>;
  alarm_only_violations?: Array<{ violation_name: string; action: string }>;
}

export interface PushRequest {
  namespace: string;
  tenant_url?: string;
  api_token?: string;
  objects: string[];
}
