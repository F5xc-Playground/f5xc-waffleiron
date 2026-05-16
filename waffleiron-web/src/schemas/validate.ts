import Ajv from 'ajv';
import { schemas } from './xc-schemas';

const ajv = new Ajv({ allErrors: true, strict: false });

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateXCObject(objectType: string, data: unknown): ValidationResult {
  const schema = schemas[objectType];
  if (!schema) {
    return { valid: true, errors: [] };
  }

  const validate = ajv.compile(schema);
  const valid = validate(data);

  if (valid) {
    return { valid: true, errors: [] };
  }

  const errors = (validate.errors ?? []).map((err) => {
    const path = err.instancePath || '/';
    return `${path}: ${err.message}`;
  });

  return { valid: false, errors };
}
