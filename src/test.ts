import { createSanitizerSystemAsync } from "./sanitizers/factory.js";

(async () => {
  const result = await createSanitizerSystemAsync();
  const report = await result.diagnostics.runAll({deep:true});

  console.log("Diagnostics Summary:");
  console.table(report.summary);

  console.log("Detailed Results:");
  console.dir(report.results, { depth: null });
})();
