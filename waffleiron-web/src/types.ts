export interface ConversionSession {
  id: string;
  status: 'parsed' | 'analyzed' | 'translated';
  policy_name: string;
}

export interface SignatureSetInfo {
  name: string;
  enabled: boolean;
}

export interface PolicyInfo {
  name: string;
  enforcement_mode: 'blocking' | 'transparent';
  encoding: string;
  signature_accuracy: string;
  staging_enabled: boolean;
  threat_campaigns_enabled: boolean;
  features: Record<string, boolean>;
  entity_counts: Record<string, number>;
  signature_sets: SignatureSetInfo[];
}

export interface AnalysisResult {
  policy_info: PolicyInfo;
  summary: ConversionSummary;
  alarm_only_signatures: AlarmOnlySignature[];
  alarm_only_violations: AlarmOnlyViolation[];
  untranslatable: UntranslatableSummary;
  bot_gaps: BotGap[];
  blocking_page_gaps: BlockingPageGap[];
  ip_intel_gaps: IpIntelGap[];
  warnings: LimitWarning[];
}

export interface LimitWarning {
  resource: string;
  count: number;
  limit: number;
  message: string;
}

export interface UntranslatableSummary {
  custom_signature_count: number;
  session_tracking_enabled: boolean;
  session_hijacking_enabled: boolean;
  brute_force_enabled: boolean;
  custom_signatures: CustomSignature[];
}

export interface CustomSignature {
  id: number;
  name: string;
  pattern: string;
  scope: string;
}

export interface BotGap {
  category: string;
  asm_action: string;
  reason: string;
}

export interface BlockingPageGap {
  variable: string;
  reason: string;
}

export interface IpIntelGap {
  category: string;
  reason: string;
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
  action: 'exclude' | 'enforce';
}

export interface AlarmOnlyViolation {
  violation_name: string;
  action: 'disable' | 'enforce';
}

export interface TranslationOutputs {
  'app-firewall'?: object;
  'waf-exclusion-policy'?: object;
  'service-policy'?: object;
  '_advisory:http_lb_patch'?: object;
}

export interface PushResult {
  object_type: string;
  success: boolean;
  error?: string;
  namespace?: string;
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

export interface PolicyOverrides {
  enforcement_mode?: 'blocking' | 'transparent';
  signature_accuracy?: string;
  staging_enabled?: boolean;
  threat_campaigns_enabled?: boolean;
}

export interface PushRequest {
  tenant_url?: string;
  api_token?: string;
  objects: string[];
}
