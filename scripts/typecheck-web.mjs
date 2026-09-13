import { existsSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const platformNames = {
  "darwin-arm64": "darwin-arm64",
  "darwin-x64": "darwin-x64",
  "linux-arm64": "linux-arm64",
  "linux-x64": "linux-x64",
  "win32-arm64": "win32-arm64",
  "win32-x64": "win32-x64"
};

const platformKey = `${process.platform}-${process.arch}`;
const packageName = platformNames[platformKey];
const webDirectory = join(process.cwd(), "web");
const platformPackage = packageName
  ? join(webDirectory, "node_modules", "@typescript", `typescript-${packageName}`)
  : null;

if (!platformPackage || !existsSync(platformPackage)) {
  console.error(
    `TypeScript's platform package is missing for ${platformKey}. ` +
      "Run `npm --prefix web ci --ignore-scripts` on this machine, then retry."
  );
  process.exit(1);
}

const result = spawnSync("npx", ["tsc", "-b"], {
  cwd: webDirectory,
  stdio: "inherit"
});

process.exit(result.status ?? 1);
