#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function toPosixPath(value) {
  return value.split(path.sep).join('/');
}

function collectSourceFiles(dir) {
  const out = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectSourceFiles(absolute));
      continue;
    }
    if (!entry.isFile()) continue;
    if (!absolute.endsWith('.ts') && !absolute.endsWith('.tsx')) continue;
    if (absolute.endsWith('.d.ts')) continue;
    out.push(absolute);
  }
  return out;
}

function stripImportSuffix(specifier) {
  return String(specifier || '').replace(/[?#].*$/, '');
}

function resolveImportTarget(fromFile, specifier, fileSet, signingRoot, repoRoot) {
  const raw = stripImportSuffix(specifier);
  if (!raw) return null;

  let basePath;
  if (raw.startsWith('.')) {
    basePath = path.resolve(path.dirname(fromFile), raw);
  } else if (raw.startsWith('@/core/signing/')) {
    basePath = path.join(signingRoot, raw.slice('@/core/signing/'.length));
  } else if (raw.startsWith('client/src/core/signing/')) {
    basePath = path.join(repoRoot, raw);
  } else {
    return null;
  }

  const parsed = path.parse(basePath);
  const candidates = [];
  if (parsed.ext) {
    candidates.push(basePath);
    if (parsed.ext === '.js' || parsed.ext === '.mjs' || parsed.ext === '.cjs') {
      candidates.push(path.join(parsed.dir, `${parsed.name}.ts`));
      candidates.push(path.join(parsed.dir, `${parsed.name}.tsx`));
    }
  } else {
    candidates.push(`${basePath}.ts`);
    candidates.push(`${basePath}.tsx`);
    candidates.push(path.join(basePath, 'index.ts'));
    candidates.push(path.join(basePath, 'index.tsx'));
  }

  for (const candidate of candidates) {
    if (fileSet.has(candidate)) return candidate;
  }
  return null;
}

function readImports(filePath) {
  const source = fs.readFileSync(filePath, 'utf8');
  const imports = [];
  const staticImportRegex = /(?:import|export)\s+(?:type\s+)?(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g;
  const dynamicImportRegex = /import\(\s*['"]([^'"]+)['"]\s*\)/g;

  let match;
  while ((match = staticImportRegex.exec(source)) !== null) {
    imports.push(match[1]);
  }
  while ((match = dynamicImportRegex.exec(source)) !== null) {
    imports.push(match[1]);
  }

  return imports;
}

function buildGraph(files, signingRoot, repoRoot) {
  const fileSet = new Set(files);
  const graph = new Map();

  for (const filePath of files) {
    const imports = readImports(filePath);
    const next = new Set();
    for (const specifier of imports) {
      const resolved = resolveImportTarget(filePath, specifier, fileSet, signingRoot, repoRoot);
      if (!resolved || resolved === filePath) continue;
      next.add(resolved);
    }
    graph.set(filePath, Array.from(next));
  }

  return graph;
}

function stronglyConnectedComponents(graph) {
  let index = 0;
  const stack = [];
  const onStack = new Set();
  const indices = new Map();
  const lowLinks = new Map();
  const sccs = [];

  function strongConnect(node) {
    indices.set(node, index);
    lowLinks.set(node, index);
    index += 1;
    stack.push(node);
    onStack.add(node);

    const neighbors = graph.get(node) || [];
    for (const neighbor of neighbors) {
      if (!indices.has(neighbor)) {
        strongConnect(neighbor);
        lowLinks.set(node, Math.min(lowLinks.get(node), lowLinks.get(neighbor)));
      } else if (onStack.has(neighbor)) {
        lowLinks.set(node, Math.min(lowLinks.get(node), indices.get(neighbor)));
      }
    }

    if (lowLinks.get(node) === indices.get(node)) {
      const component = [];
      while (stack.length > 0) {
        const member = stack.pop();
        onStack.delete(member);
        component.push(member);
        if (member === node) break;
      }
      sccs.push(component);
    }
  }

  for (const node of graph.keys()) {
    if (!indices.has(node)) {
      strongConnect(node);
    }
  }

  return sccs;
}

function hasSelfLoop(node, graph) {
  const neighbors = graph.get(node) || [];
  return neighbors.includes(node);
}

function describeCycle(component, repoRoot) {
  return component
    .map((absPath) => toPosixPath(path.relative(repoRoot, absPath)))
    .sort();
}

function main() {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(scriptDir, '../..');
  const signingRoot = path.join(repoRoot, 'client/src/core/signing');
  const apiRoot = path.join(signingRoot, 'api');

  if (!fs.existsSync(signingRoot)) {
    console.error('[check-signing-api-cycles] signing root is missing:', signingRoot);
    process.exit(1);
  }

  const files = collectSourceFiles(signingRoot);
  const graph = buildGraph(files, signingRoot, repoRoot);
  const sccs = stronglyConnectedComponents(graph);

  const apiCrossLayerCycles = [];
  for (const component of sccs) {
    const isCycle =
      component.length > 1 || (component.length === 1 && hasSelfLoop(component[0], graph));
    if (!isCycle) continue;

    const hasApiNode = component.some((absPath) => absPath.startsWith(`${apiRoot}${path.sep}`));
    const hasLowerLayerNode = component.some(
      (absPath) => !absPath.startsWith(`${apiRoot}${path.sep}`),
    );
    if (!hasApiNode || !hasLowerLayerNode) continue;

    apiCrossLayerCycles.push(describeCycle(component, repoRoot));
  }

  if (!apiCrossLayerCycles.length) {
    console.log('[check-signing-api-cycles] OK: no api/lower-layer cycles detected');
    return;
  }

  console.error('[check-signing-api-cycles] failed: detected api/lower-layer cycles');
  for (let i = 0; i < apiCrossLayerCycles.length; i += 1) {
    const cycle = apiCrossLayerCycles[i];
    console.error(`  cycle-${i + 1}:`);
    for (const filePath of cycle) {
      console.error(`    - ${filePath}`);
    }
  }
  process.exit(1);
}

main();
