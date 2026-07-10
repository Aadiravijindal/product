export interface DiffRow {
  type: 'same' | 'change' | 'del' | 'add';
  left: string | null;
  leftNo: number | null;
  right: string | null;
  rightNo: number | null;
}

/** Simple LCS-based line diff rendered as aligned side-by-side rows. */
export function sideBySideDiff(before: string, after: string): DiffRow[] {
  const a = before.replace(/\r\n/g, '\n').split('\n');
  const b = after.replace(/\r\n/g, '\n').split('\n');
  const n = a.length;
  const m = b.length;

  // LCS table (files here are small; O(n*m) is fine)
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const rows: DiffRow[] = [];
  let i = 0;
  let j = 0;
  let pendingDel: { line: string; no: number }[] = [];
  let pendingAdd: { line: string; no: number }[] = [];

  const flush = () => {
    const len = Math.max(pendingDel.length, pendingAdd.length);
    for (let k = 0; k < len; k++) {
      const d = pendingDel[k];
      const ad = pendingAdd[k];
      rows.push({
        type: d && ad ? 'change' : d ? 'del' : 'add',
        left: d ? d.line : null,
        leftNo: d ? d.no : null,
        right: ad ? ad.line : null,
        rightNo: ad ? ad.no : null,
      });
    }
    pendingDel = [];
    pendingAdd = [];
  };

  while (i < n && j < m) {
    if (a[i] === b[j]) {
      flush();
      rows.push({ type: 'same', left: a[i], leftNo: i + 1, right: b[j], rightNo: j + 1 });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      pendingDel.push({ line: a[i], no: i + 1 });
      i++;
    } else {
      pendingAdd.push({ line: b[j], no: j + 1 });
      j++;
    }
  }
  while (i < n) pendingDel.push({ line: a[i], no: ++i });
  while (j < m) pendingAdd.push({ line: b[j], no: ++j });
  flush();
  return rows;
}
