import { Zap, CheckCircle2 } from "lucide-react";

interface Props {
  narrative: string;
  recommendations: string[];
}

export default function AIExplanation({ narrative, recommendations }: Props) {
  // Render markdown-style **bold** in narrative
  const renderNarrative = (text: string) => {
    const parts = text.split(/(\*\*[^*]+\*\*)/g);
    return parts.map((part, i) =>
      part.startsWith("**") && part.endsWith("**") ? (
        <strong key={i} className="text-slate-100 font-semibold">
          {part.slice(2, -2)}
        </strong>
      ) : (
        <span key={i}>{part}</span>
      )
    );
  };

  const paragraphs = narrative.split(/\n\n+/).filter(Boolean);

  return (
    <div className="card-surface p-6 rounded-2xl space-y-5">
      <div className="flex items-center gap-2">
        <Zap className="w-5 h-5 text-yellow-400" />
        <h2 className="font-semibold text-slate-200">AI Threat Narrative</h2>
        <span className="ml-auto text-xs text-slate-300 bg-slate-800 px-2 py-0.5 rounded-full">
          Claude
        </span>
      </div>

      {/* Narrative paragraphs */}
      <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
        {paragraphs.map((p, i) => (
          <p key={i}>{renderNarrative(p)}</p>
        ))}
      </div>

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div className="border-t border-white/5 pt-5 space-y-2">
          <p className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
            Security Recommendations
          </p>
          <ul className="space-y-2">
            {recommendations.map((rec, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
