import fs from 'fs';
import path from 'path';

export interface SampleRepo {
  id: string;
  name: string;
  language: string;
  description: string;
  files: { path: string; content: string }[];
}

const REPO_DEFS: { id: string; name: string; language: string; description: string; dir: string }[] = [
  {
    id: 'payment-service',
    name: 'payment-service',
    language: 'Python',
    description: 'Payment signing microservice — signs settlement transactions with RSA-2048',
    dir: 'payment-service',
  },
  {
    id: 'auth-service',
    name: 'auth-service',
    language: 'Java',
    description: 'Internal auth service — RSA session assertions and a pinned legacy TLS config',
    dir: 'auth-service',
  },
  {
    id: 'api-gateway',
    name: 'api-gateway',
    language: 'Node.js',
    description: 'API gateway — issues RS256 JWTs consumed by every downstream service',
    dir: 'api-gateway',
  },
  {
    id: 'infra-configs',
    name: 'infra-configs',
    language: 'IaC / Config',
    description: 'Beyond source code — legacy TLS in nginx, Terraform-provisioned RSA keys, a Kubernetes TLS secret',
    dir: 'infra-configs',
  },
];

function readDirRecursive(root: string, rel = ''): { path: string; content: string }[] {
  const out: { path: string; content: string }[] = [];
  const abs = path.join(root, rel);
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...readDirRecursive(root, relPath));
    } else {
      out.push({ path: relPath, content: fs.readFileSync(path.join(root, relPath), 'utf8') });
    }
  }
  return out;
}

let cache: SampleRepo[] | null = null;

export function getSampleRepos(): SampleRepo[] {
  if (cache) return cache;
  const base = path.join(process.cwd(), 'sample-repos');
  cache = REPO_DEFS.map((def) => ({
    id: def.id,
    name: def.name,
    language: def.language,
    description: def.description,
    files: readDirRecursive(path.join(base, def.dir)),
  }));
  return cache;
}

export function getSampleRepo(id: string): SampleRepo | undefined {
  return getSampleRepos().find((r) => r.id === id);
}
