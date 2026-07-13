import { NextResponse } from 'next/server';
import { claudeAvailable } from '@/lib/claude';
import { PATTERN_COUNT } from '@/lib/scanner';

/**
 * GET /api/health — readiness probe for load balancers, uptime checks, and
 * the verification harness. Reports whether the live Claude pipeline is
 * configured without ever leaking the key.
 */
export async function GET() {
  return NextResponse.json({
    status: 'ok',
    service: 'recrypt',
    detectionPatterns: PATTERN_COUNT,
    liveAnalysis: claudeAvailable(),
    time: new Date().toISOString(),
  });
}
