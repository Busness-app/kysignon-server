import { useCallback, useEffect, useState } from 'react';
import { apiJson, errorMessage } from '../api';
import type { DirectoryPage } from '../types';

export const pageSize = 25;
export function useDirectoryPage<T>(url: string, parse: (value: unknown) => DirectoryPage<T>) {
  const [page, setPage] = useState<DirectoryPage<T> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision(value => value + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    setPage(null);
    setError(null);
    void apiJson(url, parse, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) setPage(value);
    }).catch(err => {
      if (!controller.signal.aborted) setError(errorMessage(err, 'Could not load directory'));
    });
    return () => controller.abort();
  }, [url, parse, revision]);
  return { page, error, reload };
}

export function Pager({ page, offset, onChange }: {
  page: DirectoryPage<unknown> | null; offset: number; onChange: (offset: number) => void;
}) {
  return <div className="pagination-bar">
    <span className="pagination-info">{page ? `${page.total} total · Page ${Math.floor(offset / pageSize) + 1}` : 'Loading...'}</span>
    <div className="pagination-nav">
      <button className="pagination-page-btn" disabled={!page || offset === 0} onClick={() => onChange(Math.max(0, offset - pageSize))}>Previous</button>
      <button className="pagination-page-btn" disabled={!page || offset + pageSize >= page.total} onClick={() => onChange(offset + pageSize)}>Next</button>
    </div>
  </div>;
}
