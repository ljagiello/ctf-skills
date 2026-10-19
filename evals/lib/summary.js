// Print a Markdown summary of promptfoo result files (written with -o *.json).
// Usage: node lib/summary.js out/routing.json [out/solve.json ...]
// In CI the output is appended to $GITHUB_STEP_SUMMARY.

import fs from 'node:fs';

const pct = (value) => `${Math.round(value * 100)}%`;
const status = (row) => (row.success ? 'pass' : row.failureReason === 2 ? 'error' : 'fail');

for (const file of process.argv.slice(2)) {
  if (!fs.existsSync(file)) {
    console.log(`> ${file}: no results (eval did not run or crashed)\n`);
    continue;
  }
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const rows = data.results.results;
  console.log(`### ${data.config?.description ?? file}\n`);

  const byProvider = Map.groupBy(rows, (row) => row.provider.label ?? row.provider.id);
  const metrics = [...new Set(rows.flatMap((row) => Object.keys(row.namedScores ?? {})))].sort();
  console.log(`| provider | pass | fail | error | ${metrics.join(' | ')} | cost (USD) |`);
  console.log(`|---|---|---|---|${metrics.map(() => '---|').join('')}---|`);
  for (const [provider, group] of byProvider) {
    const count = (kind) => group.filter((row) => status(row) === kind).length;
    const metricCells = metrics.map((metric) => {
      const scores = group.map((row) => row.namedScores?.[metric]).filter((s) => s !== undefined);
      return scores.length ? pct(scores.reduce((a, b) => a + b, 0) / scores.length) : '-';
    });
    const cost = group.reduce((sum, row) => sum + (row.cost ?? 0), 0);
    console.log(
      `| ${provider} | ${count('pass')}/${group.length} | ${count('fail')} | ${count('error')} | ${metricCells.join(' | ')} | ${cost.toFixed(2)} |`,
    );
  }

  const problems = rows.filter((row) => !row.success);
  if (problems.length > 0) {
    console.log('\n| case | provider | result | reason |\n|---|---|---|---|');
    for (const row of problems) {
      const reason = (row.error ?? row.gradingResult?.reason ?? '').replace(/\s+/g, ' ').slice(0, 200);
      console.log(
        `| ${row.testCase?.description ?? row.testIdx} | ${row.provider.label ?? row.provider.id} | ${status(row)} | ${reason.replaceAll('|', '\\|')} |`,
      );
    }
  }
  console.log('');
}
