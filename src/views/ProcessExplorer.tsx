import React, { useMemo, useState } from 'react';
import { 
  useReactTable, 
  getCoreRowModel, 
  flexRender, 
  createColumnHelper,
  getSortedRowModel,
  SortingState,
  getFilteredRowModel
} from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useAppStore, Process } from '../store';
import { cn, Button, Input } from '../lib/components';
import { Search, RefreshCw, Filter, Play, Square, MoreVertical } from 'lucide-react';

// Mock data generator
const generateMockProcesses = (count: number): Process[] => {
  const names = ['explorer.exe', 'chrome.exe', 'svchost.exe', 'discord.exe', 'spotify.exe', 'steam.exe', 'code.exe', 'cmd.exe', 'taskmgr.exe'];
  return Array.from({ length: count }, (_, i) => ({
    pid: i + 1000,
    name: names[Math.floor(Math.random() * names.length)],
    arch: Math.random() > 0.3 ? 'x64' : 'x86',
    cpu: Math.random() * 5,
    memory: `${(Math.random() * 500).toFixed(1)} MB`,
    threads: Math.floor(Math.random() * 50) + 1,
    path: `C:\\Windows\\System32\\${names[Math.floor(Math.random() * names.length)]}`,
    status: Math.random() > 0.9 ? 'Suspended' : 'Running',
  }));
};

export const ProcessExplorer = () => {
  const attachProcess = useAppStore(state => state.attachProcess);
  const [data] = useState(() => generateMockProcesses(2000));
  const [sorting, setSorting] = useState<SortingState>([]);
  const [globalFilter, setGlobalFilter] = useState('');

  const columnHelper = createColumnHelper<Process>();

  const columns = useMemo(() => [
    columnHelper.accessor('pid', {
      header: 'PID',
      cell: info => <span className="font-mono text-neutral-500">{info.getValue()}</span>,
      size: 80,
    }),
    columnHelper.accessor('name', {
      header: 'Process Name',
      cell: info => (
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 bg-neutral-800 rounded flex items-center justify-center text-[10px] text-neutral-500 font-bold">
            {info.getValue().charAt(0).toUpperCase()}
          </div>
          <span className="font-semibold text-neutral-200">{info.getValue()}</span>
        </div>
      ),
      size: 200,
    }),
    columnHelper.accessor('arch', {
      header: 'Arch',
      cell: info => (
        <span className={cn(
          "px-1.5 py-0.5 rounded text-[10px] font-bold uppercase",
          info.getValue() === 'x64' ? "bg-accent-blue/10 text-accent-blue" : "bg-neutral-800 text-neutral-400"
        )}>
          {info.getValue()}
        </span>
      ),
      size: 70,
    }),
    columnHelper.accessor('cpu', {
      header: 'CPU %',
      cell: info => (
        <div className="w-full flex items-center gap-2">
          <div className="flex-1 bg-neutral-800 h-1.5 rounded-full overflow-hidden">
            <div className="bg-accent-blue h-full" style={{ width: `${info.getValue() * 10}%` }} />
          </div>
          <span className="font-mono text-[11px] w-8 text-right text-neutral-500">{info.getValue().toFixed(1)}</span>
        </div>
      ),
      size: 120,
    }),
    columnHelper.accessor('memory', {
      header: 'Memory',
      cell: info => <span className="font-mono text-neutral-300">{info.getValue()}</span>,
      size: 100,
    }),
    columnHelper.accessor('status', {
      header: 'Status',
      cell: info => (
        <span className={cn(
          "text-[11px] font-medium",
          info.getValue() === 'Running' ? "text-green-500" : "text-yellow-500"
        )}>
          {info.getValue()}
        </span>
      ),
      size: 90,
    }),
    columnHelper.accessor('path', {
      header: 'Path',
      cell: info => <span className="truncate text-neutral-600 italic text-[11px]">{info.getValue()}</span>,
    }),
  ], [columnHelper]);

  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  const tableContainerRef = React.useRef<HTMLDivElement>(null);
  const { rows } = table.getRowModel();

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => 32,
    overscan: 10,
  });

  return (
    <div className="flex flex-col h-full bg-neutral-950">
      {/* Toolbar */}
      <div className="p-2 border-b border-neutral-900 bg-neutral-900/50 flex items-center justify-between">
        <div className="flex items-center gap-2 flex-1 max-w-sm">
          <div className="relative w-full">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-neutral-600" />
            <input 
              value={globalFilter}
              onChange={e => setGlobalFilter(e.target.value)}
              placeholder="Filter processes..." 
              className="w-full bg-neutral-950 border border-neutral-800 rounded h-8 pl-8 pr-3 text-xs focus:outline-none focus:border-neutral-700 transition-colors"
            />
          </div>
          <Button variant="outline" size="sm" className="shrink-0 h-8">
            <Filter size={14} className="mr-2" />
            Filter
          </Button>
        </div>
        
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" className="h-8 text-neutral-500 hover:text-neutral-200">
            <RefreshCw size={14} className="mr-2" />
            Refresh
          </Button>
          <div className="w-[1px] h-4 bg-neutral-800 mx-2" />
          <Button variant="primary" size="sm" className="h-8">
            <Play size={14} className="mr-2" />
            Attach Selected
          </Button>
        </div>
      </div>

      {/* Table Container */}
      <div 
        ref={tableContainerRef}
        className="flex-1 overflow-auto bg-neutral-950 relative"
      >
        <table className="w-full text-left border-collapse table-fixed">
          <thead className="sticky top-0 z-20 bg-neutral-900 border-b border-neutral-800 shadow-sm">
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map(header => (
                  <th 
                    key={header.id}
                    onClick={header.column.getToggleSortingHandler()}
                    className="px-3 py-2 text-[11px] font-bold text-neutral-500 uppercase tracking-wider cursor-pointer hover:bg-neutral-800 transition-colors"
                    style={{ width: header.getSize() }}
                  >
                    <div className="flex items-center gap-2">
                       {flexRender(header.column.columnDef.header, header.getContext())}
                       {header.column.getIsSorted() && (
                          <span className="text-accent-blue">{header.column.getIsSorted() === 'asc' ? '↑' : '↓'}</span>
                       )}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody
            style={{
              height: `${rowVirtualizer.getTotalSize()}px`,
              position: 'relative',
            }}
          >
            {rowVirtualizer.getVirtualItems().map(virtualRow => {
              const row = rows[virtualRow.index];
              return (
                <tr
                  key={row.id}
                  data-index={virtualRow.index}
                  ref={rowVirtualizer.measureElement}
                  onDoubleClick={() => attachProcess(row.original)}
                  className="absolute left-0 w-full hover:bg-accent-blue/10 cursor-pointer transition-colors group border-b border-neutral-900/50"
                  style={{
                    transform: `translateY(${virtualRow.start}px)`,
                  }}
                >
                  {row.getVisibleCells().map(cell => (
                    <td 
                      key={cell.id} 
                      className="px-3 py-1.5 whitespace-nowrap overflow-hidden text-ellipsis border-r border-neutral-900/30"
                      style={{ width: cell.column.getSize() }}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
        
        {rows.length === 0 && (
          <div className="h-40 flex flex-col items-center justify-center text-neutral-600 gap-2">
            <Search size={32} strokeWidth={1} />
            <p className="text-sm">No processes found matching your filter.</p>
          </div>
        )}
      </div>

      {/* Status Bar */}
      <div className="h-6 bg-neutral-900 border-t border-neutral-800 flex items-center px-3 justify-between text-[10px] font-medium text-neutral-500">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
            <span>SYSTEM MONITORING ACTIVE</span>
          </div>
          <span>PROCESSES: {data.length}</span>
          <span>LOAD: 1.2%</span>
        </div>
        <div className="flex items-center gap-4">
          <span>UPTIME: 02:44:12</span>
          <span className="text-accent-blue">READY</span>
        </div>
      </div>
    </div>
  );
};
