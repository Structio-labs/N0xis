import React, { useRef, useMemo, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { cn, Button } from '../lib/components';
import { Search, ArrowRight as Jump, Save, Redo, Undo, Binary, Bookmark } from 'lucide-react';

const ROWS_PER_PAGE = 16;

const generateMockMemory = (count: number) => {
  return Array.from({ length: count }, () => Math.floor(Math.random() * 256));
};

export const HexViewer = () => {
  const [memory] = useState(() => generateMockMemory(1024 * 64)); // 64KB mock
  const [baseAddress] = useState(0x00400000);
  const containerRef = useRef<HTMLDivElement>(null);
  
  const rowCount = Math.ceil(memory.length / 16);

  const rowVirtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => containerRef.current,
    estimateSize: () => 22,
    overscan: 10,
  });

  const getByteColor = (byte: number) => {
    if (byte === 0x00) return 'text-neutral-700';
    if (byte >= 0x20 && byte <= 0x7E) return 'text-neutral-300';
    if (byte === 0xFF) return 'text-red-500 font-bold';
    return 'text-accent-blue';
  };

  const toHex = (num: number, padding: number = 2) => {
    return num.toString(16).toUpperCase().padStart(padding, '0');
  };

  const toAscii = (byte: number) => {
    return byte >= 0x20 && byte <= 0x7E ? String.fromCharCode(byte) : '.';
  };

  return (
    <div className="flex flex-col h-full bg-neutral-950 font-mono">
      {/* Toolbar */}
      <div className="p-2 border-b border-neutral-900 bg-neutral-900/50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="relative group">
             <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-neutral-600" />
             <input placeholder="0x00400000" className="bg-neutral-950 border border-neutral-800 rounded h-7 pl-7 pr-2 text-[11px] w-32 focus:border-accent-blue outline-none transition-colors" />
          </div>
          <Button variant="ghost" size="xs" className="h-7"><Jump size={14} className="mr-1" /> Jump</Button>
          <div className="w-[1px] h-4 bg-neutral-800 mx-1" />
          <Button variant="ghost" size="xs" className="h-7"><Undo size={14} /></Button>
          <Button variant="ghost" size="xs" className="h-7"><Redo size={14} /></Button>
          <Button variant="ghost" size="xs" className="h-7"><Save size={14} /></Button>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="ghost" size="xs" className="h-7"><Binary size={14} className="mr-1" /> Scan Pattern</Button>
          <Button variant="ghost" size="xs" className="h-7"><Bookmark size={14} className="mr-1" /> Bookmarks</Button>
        </div>
      </div>

      {/* Hex Grid Header */}
      <div className="bg-neutral-900/30 border-b border-neutral-900 px-4 py-1 flex items-center text-[10px] font-bold text-neutral-600 uppercase tracking-tighter">
        <div className="w-24">Address</div>
        <div className="grow flex justify-around px-4">
          {Array.from({ length: 16 }, (_, i) => (
            <span key={i} className="w-6 text-center">{toHex(i)}</span>
          ))}
        </div>
        <div className="w-40 text-center">ASCII</div>
      </div>

      {/* Main Viewport */}
      <div 
        ref={containerRef}
        className="flex-1 overflow-auto bg-neutral-950 select-text scroll-smooth"
      >
        <div
          style={{
            height: `${rowVirtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const startIdx = virtualRow.index * 16;
            const bytes = memory.slice(startIdx, startIdx + 16);
            const address = baseAddress + startIdx;

            return (
              <div
                key={virtualRow.key}
                className="absolute top-0 left-0 w-full flex items-center px-4 hover:bg-neutral-900/50 text-[12px] group leading-none h-[22px]"
                style={{
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                {/* Address Column */}
                <div className="w-24 shrink-0 text-neutral-600 group-hover:text-neutral-400 font-bold transition-colors select-none">
                  {toHex(address, 8)}
                </div>

                {/* Hex Bytes Column */}
                <div className="grow flex justify-around px-4 items-center">
                  {bytes.map((byte, i) => (
                    <span 
                      key={i} 
                      className={cn(
                        "w-6 text-center cursor-pointer hover:bg-accent-blue hover:text-white rounded transition-all",
                        getByteColor(byte)
                      )}
                    >
                      {toHex(byte)}
                    </span>
                  ))}
                  {/* Fill empty spaces if row is incomplete */}
                  {Array.from({ length: 16 - bytes.length }).map((_, i) => (
                    <span key={`empty-${i}`} className="w-6" />
                  ))}
                </div>

                {/* ASCII Column */}
                <div className="w-40 shrink-0 border-l border-neutral-900 pl-4 flex justify-between text-neutral-500 select-none">
                  {bytes.map((byte, i) => (
                    <span key={`ascii-${i}`} className={cn("inline-block", byte < 0x20 || byte > 0x7E ? "text-neutral-800" : "text-neutral-400")}>
                      {toAscii(byte)}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Info Bar */}
      <div className="h-6 bg-neutral-900 border-t border-neutral-800 flex items-center px-4 justify-between text-[10px] text-neutral-500 uppercase font-bold">
        <div className="flex gap-4">
          <span>VALUE: 0x00</span>
          <span>OFFSET: +0x0000</span>
          <span>PROTECTION: PAGE_EXECUTE_READWRITE</span>
        </div>
        <div className="flex gap-4">
          <span>REGION: .text</span>
          <span className="text-accent-blue">STABLE</span>
        </div>
      </div>
    </div>
  );
};
