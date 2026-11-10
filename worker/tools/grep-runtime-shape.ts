import { probeGrepRuntimeShape } from "./grep-runtime-probe.ts";

probeGrepRuntimeShape().then((report) => {
  console.log(JSON.stringify(report));
}).catch(() => {
  console.error("Worker search request shape could not be confirmed safely.");
  process.exitCode = 2;
});
