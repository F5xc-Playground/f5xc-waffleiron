import { useState, useCallback, useEffect, useRef } from 'react';
import JSZip from 'jszip';
import { useConversion } from '../context/ConversionContext';
import { getReport } from '../api';
import JsonViewer from '../components/JsonViewer';
import GapReport from '../components/GapReport';
import PushModal from '../components/PushModal';
import type { TranslationOutputs } from '../types';

const OBJECT_TYPES = [
  { key: 'app_firewall', label: 'App Firewall' },
  { key: 'exclusion_policy', label: 'WAF Exclusion Policy' },
  { key: 'service_policy', label: 'Service Policy' },
  { key: 'http_lb_patch', label: 'HTTP LB Patch' },
] as const;

type OutputKey = (typeof OBJECT_TYPES)[number]['key'];

function getAvailableTabs(outputs: TranslationOutputs) {
  return OBJECT_TYPES.filter(
    (t) => outputs[t.key as keyof TranslationOutputs] !== undefined,
  );
}

export default function ReviewView() {
  const { state } = useConversion();
  const [activeTab, setActiveTab] = useState<OutputKey | null>(null);
  const [zipping, setZipping] = useState(false);
  const [showPushModal, setShowPushModal] = useState(false);
  const initializedRef = useRef(false);

  const outputs = state.outputs;
  const sessionId = state.sessionId;

  const tabs = outputs ? getAvailableTabs(outputs) : [];

  useEffect(() => {
    if (!initializedRef.current && tabs.length > 0) {
      setActiveTab(tabs[0].key);
      initializedRef.current = true;
    }
  }, [tabs]);

  const activeData = activeTab && outputs
    ? outputs[activeTab as keyof TranslationOutputs]
    : undefined;

  const handleDownloadZip = useCallback(async () => {
    if (!outputs || !sessionId) return;

    setZipping(true);
    try {
      const zip = new JSZip();

      for (const t of OBJECT_TYPES) {
        const data = outputs[t.key as keyof TranslationOutputs];
        if (data) {
          zip.file(`${t.key}.json`, JSON.stringify(data, null, 2));
        }
      }

      try {
        const markdown = await getReport(sessionId, 'markdown');
        zip.file('gap_report.md', markdown);
      } catch {
        // Gap report is optional
      }

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waffleiron-${sessionId}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to create ZIP:', err);
    } finally {
      setZipping(false);
    }
  }, [outputs, sessionId]);

  if (!outputs || !sessionId) {
    return (
      <div className="flex-1 px-6 py-4">
        <div className="mx-auto max-w-4xl rounded-lg border border-dashed border-gray-300 p-12 text-center dark:border-gray-600">
          <p className="text-gray-500 dark:text-gray-400">
            No translation outputs available.
          </p>
        </div>
      </div>
    );
  }

  const hasPushResults = state.pushResults && state.pushResults.length > 0;
  const allPushSucceeded = state.pushResults?.every((r) => r.success);

  return (
    <div className="flex-1 px-6 py-4">
      <div className="mx-auto max-w-5xl space-y-6">
        {/* Export Actions */}
        <div className="grid grid-cols-2 gap-4">
          <button
            type="button"
            onClick={handleDownloadZip}
            disabled={zipping}
            className="flex flex-col items-center gap-2 rounded-lg border border-gray-200 bg-white px-5 py-5 text-center shadow-sm transition-colors hover:border-gray-300 hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-gray-500 dark:hover:bg-gray-700"
          >
            {zipping ? (
              <svg className="h-8 w-8 animate-spin text-gray-400" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            ) : (
              <svg className="h-8 w-8 text-gray-500 dark:text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
            )}
            <span className="text-sm font-semibold text-gray-900 dark:text-white">
              {zipping ? 'Creating ZIP...' : 'Download JSON'}
            </span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              Export all objects as a ZIP archive
            </span>
          </button>

          <button
            type="button"
            onClick={() => setShowPushModal(true)}
            className="flex flex-col items-center gap-2 rounded-lg border border-gray-200 bg-white px-5 py-5 text-center shadow-sm transition-colors hover:border-indigo-300 hover:bg-indigo-50 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-indigo-700 dark:hover:bg-indigo-900/20"
          >
            {hasPushResults && allPushSucceeded ? (
              <svg className="h-8 w-8 text-green-500 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            ) : (
              <svg className="h-8 w-8 text-indigo-500 dark:text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            )}
            <span className="text-sm font-semibold text-gray-900 dark:text-white">
              {hasPushResults && allPushSucceeded ? 'Pushed to XC' : 'Push to XC Tenant'}
            </span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {hasPushResults && allPushSucceeded
                ? 'Objects deployed — click to push again'
                : 'Deploy objects directly to your tenant'}
            </span>
          </button>
        </div>

        {/* Tabbed JSON Panels */}
        {tabs.length > 0 && (
          <div>
            <div className="flex border-b border-gray-200 dark:border-gray-700">
              {tabs.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  onClick={() => setActiveTab(tab.key)}
                  className={`border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                    activeTab === tab.key
                      ? 'border-indigo-600 text-indigo-600 dark:border-indigo-400 dark:text-indigo-400'
                      : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700 dark:text-gray-400 dark:hover:border-gray-600 dark:hover:text-gray-300'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="mt-3">
              {activeData && activeTab && (
                <JsonViewer
                  data={activeData}
                  title={tabs.find((t) => t.key === activeTab)?.label}
                />
              )}
            </div>
          </div>
        )}

        {/* Gap Report */}
        <GapReport sessionId={sessionId} />
      </div>

      {/* Push Modal */}
      {showPushModal && <PushModal onClose={() => setShowPushModal(false)} />}
    </div>
  );
}
