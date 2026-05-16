const xcMetadata = {
  type: 'object' as const,
  properties: {
    name: { type: 'string' as const, minLength: 1, maxLength: 64, pattern: '^[a-z0-9][a-z0-9-]*[a-z0-9]$' },
    namespace: { type: 'string' as const, minLength: 1 },
  },
  required: ['name', 'namespace'] as const,
  additionalProperties: false,
};

export const appFirewallSchema = {
  $id: 'app_firewall',
  type: 'object' as const,
  properties: {
    metadata: xcMetadata,
    spec: {
      type: 'object' as const,
      properties: {
        blocking: { type: 'object' as const },
        monitoring: { type: 'object' as const },
        detection_settings: { type: 'object' as const },
        bot_protection_setting: { type: 'object' as const },
        default_bot_setting: { type: 'object' as const },
        blocking_page: { type: 'object' as const },
        use_default_blocking_page: { type: 'object' as const },
        custom_anonymization: { type: 'object' as const },
        default_anonymization: { type: 'object' as const },
        allowed_response_codes: { type: 'object' as const },
        allow_all_response_codes: { type: 'object' as const },
      },
      required: ['detection_settings'] as const,
      additionalProperties: false,
    },
  },
  required: ['metadata', 'spec'] as const,
  additionalProperties: false,
};

const exclusionRuleSchema = {
  type: 'object' as const,
  properties: {
    metadata: {
      type: 'object' as const,
      properties: { name: { type: 'string' as const } },
      required: ['name'] as const,
    },
    any_domain: { type: 'object' as const },
    any_path: { type: 'object' as const },
    path_prefix: { type: 'string' as const },
    app_firewall_detection_control: {
      type: 'object' as const,
      properties: {
        exclude_signature_contexts: {
          type: 'array' as const,
          items: {
            type: 'object' as const,
            properties: {
              signature_id: { type: 'integer' as const },
              context: { type: 'string' as const, enum: ['CONTEXT_ANY', 'CONTEXT_PARAMETER', 'CONTEXT_COOKIE'] },
              context_name: { type: 'string' as const },
            },
            required: ['signature_id', 'context', 'context_name'] as const,
          },
        },
      },
    },
    waf_skip_processing: { type: 'object' as const },
  },
  required: ['metadata'] as const,
};

export const exclusionPolicySchema = {
  $id: 'exclusion_policy',
  type: 'object' as const,
  properties: {
    metadata: xcMetadata,
    spec: {
      type: 'object' as const,
      properties: {
        waf_exclusion_rules: {
          type: 'array' as const,
          items: exclusionRuleSchema,
        },
      },
      required: ['waf_exclusion_rules'] as const,
      additionalProperties: false,
    },
  },
  required: ['metadata', 'spec'] as const,
  additionalProperties: false,
};

const servicePolicyRuleSchema = {
  type: 'object' as const,
  properties: {
    metadata: {
      type: 'object' as const,
      properties: { name: { type: 'string' as const } },
      required: ['name'] as const,
    },
    spec: {
      type: 'object' as const,
      properties: {
        action: { type: 'string' as const, enum: ['ALLOW', 'DENY'] },
        any_client: { type: 'object' as const },
        client_selector: { type: 'object' as const },
        ip_prefix_list: { type: 'object' as const },
        ip_threat_category_list: { type: 'object' as const },
        waf_action: { type: 'object' as const },
      },
      required: ['action', 'waf_action'] as const,
    },
  },
  required: ['metadata', 'spec'] as const,
};

export const servicePolicySchema = {
  $id: 'service_policy',
  type: 'object' as const,
  properties: {
    metadata: xcMetadata,
    spec: {
      type: 'object' as const,
      properties: {
        rule_list: {
          type: 'object' as const,
          properties: {
            rules: {
              type: 'array' as const,
              items: servicePolicyRuleSchema,
            },
          },
          required: ['rules'] as const,
        },
      },
      required: ['rule_list'] as const,
      additionalProperties: false,
    },
  },
  required: ['metadata', 'spec'] as const,
  additionalProperties: false,
};

export const httpLbPatchSchema = {
  $id: 'http_lb_patch',
  type: 'object' as const,
  properties: {
    csrf: {
      type: 'object' as const,
      properties: {
        enabled: { type: 'boolean' as const },
        urls: { type: 'array' as const, items: { type: 'string' as const } },
      },
      required: ['enabled', 'urls'] as const,
    },
    data_guard: {
      type: 'object' as const,
      properties: {
        enabled: { type: 'boolean' as const },
        credit_cards: { type: 'boolean' as const },
        ssn: { type: 'boolean' as const },
        custom_patterns: { type: 'array' as const, items: { type: 'string' as const } },
        exception_urls: { type: 'array' as const, items: { type: 'string' as const } },
      },
      required: ['enabled'] as const,
    },
  },
  additionalProperties: false,
};

export const schemas: Record<string, object> = {
  app_firewall: appFirewallSchema,
  exclusion_policy: exclusionPolicySchema,
  service_policy: servicePolicySchema,
  http_lb_patch: httpLbPatchSchema,
};
