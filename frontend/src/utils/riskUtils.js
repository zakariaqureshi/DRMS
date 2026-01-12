// Heuristic reductions used for playbook projections.
export const CONTROL_REDUCTION = {
  mfa: 35,
  siem_alerting: 20,
  edr: 15,
  waf: 10,
  patch_sla: 10,
  backup_testing: 5,
};

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

export const computePosture = (avgRisk) => {
  const score = Number(avgRisk) || 0;
  if (score >= 85) return { label: "CRITICAL", tone: "critical" };
  if (score >= 70) return { label: "HIGH", tone: "high" };
  if (score >= 40) return { label: "MED", tone: "med" };
  return { label: "LOW", tone: "low" };
};

export const getTopRiskDriver = (distributions = {}) => {
  const pickTop = (obj) => {
    const entries = Object.entries(obj || {});
    if (!entries.length) return null;
    return entries.reduce((acc, [name, value]) => {
      if (!acc || value > acc.value) return { name, value };
      return acc;
    }, null);
  };

  const topTactic = pickTop(distributions.byTactic || distributions.risk_by_tactic);
  const topTechnique = pickTop(distributions.byTechnique || distributions.risk_by_technique);

  return {
    tactic: topTactic?.name || "N/A",
    technique: topTechnique?.name || "N/A",
  };
};

export const computePlaybook = (findings = [], recommendations = []) => {
  if (!Array.isArray(recommendations) || recommendations.length === 0) return [];
  const findingByAsset = new Map(
    (findings || []).map((item) => [
      item.asset,
      {
        riskScore: Number(item.riskScore ?? item.risk_score) || 0,
        techniqueId: item.techniqueId || item.technique || item.technique_id || "N/A",
        tactic: item.tactic || "N/A",
        exposureScore: Number(item.exposureScore ?? item.exposure_score) || 0,
      },
    ])
  );

  const rows = recommendations
    .map((rec) => {
      if (!rec || typeof rec === "string") return null;
      const controls = Array.isArray(rec.addControls) ? rec.addControls : [];
      const prettyControls = controls.map((ctrl) => ctrl.replace(/_/g, " "));
      const reduction = controls.reduce((sum, ctrl) => sum + (CONTROL_REDUCTION[ctrl] || 0), 0);
      const cappedReduction = clamp(reduction, 0, 60);
      const finding = findingByAsset.get(rec.asset) || {};
      const riskScore = Number(finding.riskScore) || 0;
      const priority =
        riskScore >= 80 || cappedReduction >= 45 ? "P1" : riskScore >= 60 || cappedReduction >= 30 ? "P2" : "P3";

      return {
        asset: rec.asset || "Unknown",
        riskDriver: rec.relatedTechniqueId || finding.techniqueId || "N/A",
        tactic: rec.relatedTactic || finding.tactic || "N/A",
        recommendedFix: controls.length ? prettyControls.join(", ") : rec.rationale || "Review controls",
        reduction: cappedReduction,
        riskScore,
        priority,
      };
    })
    .filter(Boolean);

  rows.sort((a, b) => {
    if (b.reduction !== a.reduction) return b.reduction - a.reduction;
    return b.riskScore - a.riskScore;
  });

  console.assert(rows.every((row) => row.reduction <= 60), "Playbook reduction exceeds cap");
  return rows;
};

export const computeProjectedMetrics = (summary = {}, playbook = [], findings = []) => {
  const avgRisk = Number(summary.average_risk ?? summary.avgRisk) || 0;
  if (!Array.isArray(findings) || findings.length === 0 || playbook.length === 0) {
    return {
      projectedAvgRisk: clamp(avgRisk - avgRisk * 0.1, 0, 100),
      projectedHighRisk: summary.high_risk_assets?.length || summary.highRiskAssets || 0,
      weightedReduction: 10,
    };
  }

  const playbookByAsset = new Map(playbook.map((row) => [row.asset, row]));
  let total = 0;
  let projectedTotal = 0;
  let projectedHighRisk = 0;

  findings.forEach((item) => {
    const riskScore = Number(item.riskScore ?? item.risk_score) || 0;
    const reduction = playbookByAsset.get(item.asset)?.reduction || 0;
    const projected = clamp(riskScore * (1 - reduction / 100), 0, 100);
    total += riskScore;
    projectedTotal += projected;
    if (projected >= 70) projectedHighRisk += 1;
  });

  const projectedAvgRisk = findings.length ? projectedTotal / findings.length : avgRisk;
  const weightedReduction = total ? ((total - projectedTotal) / total) * 100 : 0;

  console.assert(projectedAvgRisk >= 0 && projectedAvgRisk <= 100, "Projected avg risk out of bounds");
  return {
    projectedAvgRisk: Math.round(projectedAvgRisk * 10) / 10,
    projectedHighRisk,
    weightedReduction: Math.round(weightedReduction * 10) / 10,
  };
};

export const getMostExposedAsset = (findings = []) => {
  if (!Array.isArray(findings) || findings.length === 0) return null;
  return findings.reduce((acc, item) => {
    const riskScore = Number(item.riskScore ?? item.risk_score) || 0;
    const exposure = Number(item.exposureScore ?? item.exposure_score) || 0;
    const score = riskScore + exposure;
    if (!acc || score > acc.score) {
      return { asset: item.asset || "Unknown", score, riskScore, exposure };
    }
    return acc;
  }, null);
};

export const getTopTechniqueByTactic = (findings = []) => {
  const map = new Map();
  findings.forEach((item) => {
    const tactic = item.tactic || "Unknown";
    const technique = item.techniqueId || item.technique || item.technique_id || "N/A";
    const riskScore = Number(item.riskScore ?? item.risk_score) || 0;
    const key = `${tactic}::${technique}`;
    const current = map.get(key) || 0;
    map.set(key, current + riskScore);
  });

  const topByTactic = {};
  map.forEach((score, key) => {
    const [tactic, technique] = key.split("::");
    if (!topByTactic[tactic] || score > topByTactic[tactic].score) {
      topByTactic[tactic] = { technique, score };
    }
  });

  return topByTactic;
};
