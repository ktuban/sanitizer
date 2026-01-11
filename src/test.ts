import { asyncCreateSanitizerSystem } from "./sanitizers/factory.js";

asyncCreateSanitizerSystem().then(async (s)=>{
const report = await s.diagnostics.runAll({deep:true});

console.log("Diagnostics Summary:");
console.table(report.summary);

console.log("Detailed Results:");
console.dir(report.results, { depth: null });
})