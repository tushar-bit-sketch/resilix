import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';

const require = createRequire('/usr/share/nodejs/');
const babel = require('/usr/share/nodejs/@babel/core');

const srcPath = path.resolve('src/App.tsx');
const tsxSource = fs.readFileSync(srcPath, 'utf8');

// Verify TypeScript + JSX syntax using @babel/core with @babel/preset-typescript and @babel/preset-react
const result = babel.transformSync(tsxSource, {
  filename: 'App.tsx',
  presets: [
    ['/usr/share/nodejs/@babel/preset-typescript', { isTSX: true, allExtensions: true }],
    ['/usr/share/nodejs/@babel/preset-react', { runtime: 'classic' }]
  ],
});

if (!result || !result.code) {
  console.error('TypeScript compilation failed.');
  process.exit(1);
}

fs.mkdirSync('dist/assets', { recursive: true });
fs.writeFileSync('dist/assets/app.compiled.js', result.code, 'utf8');

const htmlOut = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RESILIX — Secure Predictive Infrastructure Resilience System</title>
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
</head>
<body class="bg-[#F3F6FA] text-[#344256]">
  <div id="root"></div>
  <script src="/assets/app.compiled.js"></script>
</body>
</html>`;

fs.writeFileSync('dist/index.html', htmlOut, 'utf8');
console.log('✓ TypeScript AST check & static production bundle succeeded: dist/index.html + dist/assets/app.compiled.js (' + result.code.length + ' bytes)');
