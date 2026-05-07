import React from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Button } from '../lib/components';
import { Search, ChevronRight, Bookmark, ArrowRight, CornerDownRight } from 'lucide-react';

const mockInstructions = [
  { addr: '0x140001000', bytes: '48 89 5C 24 08', mnemonic: 'mov', ops: 'qword ptr [rsp+8], rbx', comment: '; Preserve RBX' },
  { addr: '0x140001005', bytes: '48 89 74 24 10', mnemonic: 'mov', ops: 'qword ptr [rsp+16], rsi', comment: '; Preserve RSI' },
  { addr: '0x14000100A', bytes: '57', mnemonic: 'push', ops: 'rdi', comment: '' },
  { addr: '0x14000100B', bytes: '48 83 EC 20', mnemonic: 'sub', ops: 'rsp, 32', comment: '; Stack allocation' },
  { addr: '0x14000100F', bytes: '48 8B 05 12 34 56 00', mnemonic: 'mov', ops: 'rax, qword ptr [0x140001234]', comment: '; Loading config' },
  { addr: '0x140001016', bytes: '48 85 C0', mnemonic: 'test', ops: 'rax, rax', comment: '; Check if NULL' },
  { addr: '0x140001019', bytes: '74 15', mnemonic: 'je', ops: '0x140001030', comment: '; Jump to cleanup' },
  { addr: '0x14000101B', bytes: 'E8 F0 FF FF FF', mnemonic: 'call', ops: '0x140001010', comment: '; Internal function' },
];

export const DisassemblyView = () => {
  return (
    <div className="flex flex-col h-full bg-neutral-950 font-mono text-xs">
       <div className="p-2 border-b border-neutral-900 bg-neutral-900/50 flex items-center gap-2">
         <div className="relative">
           <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-neutral-600" />
           <input placeholder="Jump to address..." className="bg-neutral-950 border border-neutral-800 rounded h-7 pl-7 pr-2 text-[11px] w-64 focus:border-accent-blue outline-none transition-colors" />
         </div>
         <Button variant="ghost" size="xs" className="h-7"><Bookmark size={14} className="mr-1" /> New Label</Button>
       </div>

       <div className="flex-1 overflow-auto p-4 flex flex-col gap-1">
          {mockInstructions.map((ins, i) => (
            <div key={i} className="flex items-start gap-4 hover:bg-neutral-900/50 group px-2 py-0.5 rounded transition-colors group">
              <div className="w-24 shrink-0 text-neutral-600 group-hover:text-neutral-400 select-none">
                {ins.addr}
              </div>
              <div className="w-32 shrink-0 text-neutral-700 font-mono text-[11px] whitespace-nowrap overflow-hidden">
                {ins.bytes}
              </div>
              <div className="w-20 shrink-0 text-blue-400 font-bold uppercase italic tracking-tighter">
                {ins.mnemonic}
              </div>
              <div className="w-64 shrink-0 text-neutral-200">
                {ins.ops}
              </div>
              <div className="flex-1 text-green-700 italic truncate italic">
                {ins.comment}
              </div>
              
              <div className="opacity-0 group-hover:opacity-100 flex items-center gap-2">
                 <Button variant="ghost" size="icon" className="h-5 w-5 text-neutral-600"><ChevronRight size={12} /></Button>
              </div>
            </div>
          ))}
          
          <div className="mt-4 border-t border-neutral-900 pt-4 px-2">
             <div className="flex items-center gap-2 text-neutral-500 mb-1">
               <CornerDownRight size={14} />
               <span className="text-[10px] uppercase font-bold tracking-widest text-accent-blue">Function Boundary: entry_point()</span>
             </div>
             <div className="pl-6 text-neutral-600 italic">
               ; Analysis completed in 44ms. Validating signatures...
             </div>
          </div>
       </div>
    </div>
  );
};
