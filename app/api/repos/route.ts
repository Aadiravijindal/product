import { NextResponse } from 'next/server';
import { getSampleRepos } from '@/lib/samples';
import { claudeAvailable } from '@/lib/claude';

export async function GET() {
  const repos = getSampleRepos().map((r) => ({
    id: r.id,
    name: r.name,
    language: r.language,
    description: r.description,
    fileCount: r.files.length,
  }));
  return NextResponse.json({ repos, claude: claudeAvailable() });
}
