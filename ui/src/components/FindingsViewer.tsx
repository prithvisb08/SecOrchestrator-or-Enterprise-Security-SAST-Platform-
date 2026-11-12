import React, { useState } from "react";
import { Finding, TaintStep } from "../types";

interface FindingsViewerProps {
  findings: Finding[];
  onTriage: (findingId: string) => void;
}

export const FindingsViewer: React.FC<FindingsViewerProps> = ({ findings, onTriage }) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(findings[0] || null);

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-600 text-white";
      case "HIGH":
        return "bg-orange-500 text-white";
      case "MEDIUM":
        return "bg-yellow-400 text-black";
      case "LOW":
        return "bg-blue-400 text-white";
      default:
        return "bg-gray-400 text-white";
    }
  };

  return (
    <div className="flex flex-row h-full w-full gap-4 p-4 font-sans">
      {/* Findings List Sidebar */}
      <div className="w-1/3 border rounded bg-white shadow overflow-y-auto">
        <div className="p-3 border-b bg-gray-50 font-bold text-gray-700">
          Findings ({findings.length})
        </div>
        <ul>
          {findings.map((f) => (
            <li
              key={f.id}
              onClick={() => setSelectedFinding(f)}
              className={`p-3 border-b cursor-pointer hover:bg-gray-100 ${
                selectedFinding?.id === f.id ? "bg-blue-50 border-l-4 border-l-blue-600" : ""
              }`}
            >
              <div className="flex justify-between items-center mb-1">
                <span className={`px-2 py-0.5 text-xs font-semibold rounded ${getSeverityBadgeClass(f.severity)}`}>
                  {f.severity}
                </span>
                <span className="text-xs text-gray-400">{f.rule_id}</span>
              </div>
              <div className="font-medium text-sm text-gray-900">{f.title}</div>
              <div className="text-xs text-gray-500 truncate">{f.location.file_path}:{f.location.start_line}</div>
            </li>
          ))}
        </ul>
      </div>

      {/* Finding Detail Pane */}
      {selectedFinding ? (
        <div className="flex-1 border rounded bg-white shadow p-6 overflow-y-auto">
          <div className="flex justify-between items-start mb-4">
            <div>
              <span className={`px-2.5 py-1 text-xs font-bold rounded ${getSeverityBadgeClass(selectedFinding.severity)}`}>
                {selectedFinding.severity}
              </span>
              <h2 className="text-xl font-bold text-gray-900 mt-2">{selectedFinding.title}</h2>
              <p className="text-sm text-gray-600 mt-1">{selectedFinding.description}</p>
            </div>
            <button
              onClick={() => onTriage(selectedFinding.id)}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-semibold rounded shadow hover:bg-blue-700"
            >
              Triage Status ({selectedFinding.status})
            </button>
          </div>

          <div className="mb-4">
            <h3 className="text-sm font-bold text-gray-700 mb-1">Source Location</h3>
            <div className="p-2 bg-gray-100 rounded text-xs font-mono text-gray-800">
              {selectedFinding.location.file_path} (Lines {selectedFinding.location.start_line}-{selectedFinding.location.end_line})
            </div>
            {selectedFinding.location.snippet && (
              <pre className="p-3 mt-2 bg-gray-900 text-green-400 rounded text-xs overflow-x-auto">
                <code>{selectedFinding.location.snippet}</code>
              </pre>
            )}
          </div>

          {/* Taint Flow Trace */}
          {selectedFinding.taint_path && selectedFinding.taint_path.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-bold text-gray-700 mb-2">Dataflow Taint Path</h3>
              <div className="border rounded-md p-3 bg-gray-50 space-y-2">
                {selectedFinding.taint_path.map((step: TaintStep) => (
                  <div key={step.step_number} className="flex items-start gap-2 text-xs">
                    <span className="font-bold px-1.5 py-0.5 rounded bg-gray-200 text-gray-700">
                      Step {step.step_number} ({step.type})
                    </span>
                    <span className="font-mono bg-white px-2 py-0.5 border rounded">
                      {step.expression}
                    </span>
                    <span className="text-gray-500">{step.description}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation Guidance */}
          {selectedFinding.remediation && (
            <div className="p-4 bg-blue-50 border border-blue-200 rounded">
              <h4 className="text-xs font-bold text-blue-900 uppercase">Remediation Guidance</h4>
              <p className="text-xs text-blue-800 mt-1">{selectedFinding.remediation}</p>
            </div>
          )}
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-gray-400">
          Select a finding to inspect code context and dataflow path
        </div>
      )}
    </div>
  );
};
