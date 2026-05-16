import { createContext, useContext, useReducer, type ReactNode } from 'react';
import type {
  ConversionSession,
  AnalysisResult,
  TranslationOutputs,
  PushResult,
  XCStatus,
  PolicyOverrides,
} from '../types';

export type WizardStep = 'upload' | 'analysis' | 'review';

export interface ConversionState {
  step: WizardStep;
  sessionId: string | null;
  session: ConversionSession | null;
  analysis: AnalysisResult | null;
  overrides: PolicyOverrides;
  outputs: TranslationOutputs | null;
  pushResults: PushResult[] | null;
  xcStatus: XCStatus | null;
}

type ConversionAction =
  | { type: 'UPLOAD_SUCCESS'; session: ConversionSession }
  | { type: 'ANALYSIS_LOADED'; analysis: AnalysisResult }
  | { type: 'SET_OVERRIDES'; overrides: PolicyOverrides }
  | { type: 'TRANSLATION_COMPLETE'; outputs: TranslationOutputs }
  | { type: 'OUTPUT_EDITED'; outputs: TranslationOutputs }
  | { type: 'PUSH_COMPLETE'; results: PushResult[] }
  | { type: 'XC_STATUS_LOADED'; status: XCStatus }
  | { type: 'RESET' }
  | { type: 'GO_TO_STEP'; step: WizardStep };

const initialState: ConversionState = {
  step: 'upload',
  sessionId: null,
  session: null,
  analysis: null,
  overrides: {},
  outputs: null,
  pushResults: null,
  xcStatus: null,
};

function conversionReducer(state: ConversionState, action: ConversionAction): ConversionState {
  switch (action.type) {
    case 'UPLOAD_SUCCESS':
      return {
        ...state,
        step: 'analysis',
        sessionId: action.session.id,
        session: action.session,
      };
    case 'ANALYSIS_LOADED':
      return {
        ...state,
        analysis: action.analysis,
      };
    case 'SET_OVERRIDES':
      return {
        ...state,
        overrides: action.overrides,
      };
    case 'TRANSLATION_COMPLETE':
      return {
        ...state,
        step: 'review',
        outputs: action.outputs,
      };
    case 'OUTPUT_EDITED':
      return {
        ...state,
        outputs: action.outputs,
      };
    case 'PUSH_COMPLETE':
      return {
        ...state,
        pushResults: action.results,
      };
    case 'XC_STATUS_LOADED':
      return {
        ...state,
        xcStatus: action.status,
      };
    case 'GO_TO_STEP':
      return {
        ...state,
        step: action.step,
      };
    case 'RESET':
      return initialState;
    default:
      return state;
  }
}

const ConversionContext = createContext<{
  state: ConversionState;
  dispatch: React.Dispatch<ConversionAction>;
} | null>(null);

export function ConversionProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(conversionReducer, initialState);

  return (
    <ConversionContext.Provider value={{ state, dispatch }}>
      {children}
    </ConversionContext.Provider>
  );
}

export function useConversion() {
  const context = useContext(ConversionContext);
  if (!context) {
    throw new Error('useConversion must be used within a ConversionProvider');
  }
  return context;
}
