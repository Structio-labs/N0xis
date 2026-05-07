/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { useAppStore } from './store';
import { TopBar, Sidebar, TabBar } from './components/Layout';
import { ProcessExplorer } from './views/ProcessExplorer';
import { HexViewer } from './views/HexViewer';
import { DisassemblyView } from './views/DisassemblyView';
import { Terminal, Activity, FileCode, Search, Database, List, HeartPulse, Settings } from 'lucide-react';
import { cn } from './lib/components';

const ViewRenderer = ({ type }: { type: string }) => {
  switch (type) {
    case 'processes':
      return <ProcessExplorer />;
    case 'memory':
      return <HexViewer />;
    case 'disassembly':
      return <DisassemblyView />;
    default:
      return (
        <div className="flex-1 flex flex-col items-center justify-center bg-neutral-950 text-neutral-600 gap-4">
          <Activity size={48} strokeWidth={1} />
          <div className="text-center">
            <h3 className="text-lg font-medium text-neutral-400">View Placeholder: {type}</h3>
            <p className="text-sm">This module is being initialized or requires an attached process.</p>
          </div>
        </div>
      );
  }
};

export default function App() {
  const { tabs, activeTabId, bottomPanelHeight, setBottomPanelHeight } = useAppStore();
  const activeTab = tabs.find(t => t.id === activeTabId);

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-neutral-950 font-sans">
      <TopBar />
      
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        
        <main className="flex-1 flex flex-col overflow-hidden relative">
          <TabBar />
          
          <div className="flex-1 overflow-hidden relative bg-neutral-950">
            {activeTab && <ViewRenderer type={activeTab.type} />}
          </div>

          {/* Bottom Panel (Console/Logs) */}
          <div 
            className="border-t border-neutral-800 bg-neutral-900 flex flex-col h-[200px]"
            style={{ height: `${bottomPanelHeight}px` }}
          >
            <div className="h-8 border-b border-neutral-800 flex items-center px-4 justify-between shrink-0">
              <div className="flex gap-4">
                <button className="text-[10px] font-bold uppercase tracking-widest text-accent-blue border-b-2 border-accent-blue h-full px-2">Console</button>
                <button className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 hover:text-neutral-300 h-full px-2">Logs</button>
                <button className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 hover:text-neutral-300 h-full px-2">Events</button>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-neutral-600 uppercase">Total Events: 124</span>
                <div className="w-[1px] h-3 bg-neutral-800 mx-1" />
                <button className="text-[10px] font-bold uppercase text-neutral-500 hover:text-white">Clear</button>
              </div>
            </div>
            
            <div className="flex-1 overflow-auto p-3 font-mono text-[11px] flex flex-col gap-1 leading-relaxed">
               <div className="flex gap-2">
                 <span className="text-neutral-700 select-none">[14:44:12]</span>
                 <span className="text-blue-500 font-bold uppercase shrink-0">info:</span>
                 <span className="text-neutral-300">N0x System Kernel initialized successfully. version=1.2.0-STABLE</span>
               </div>
               <div className="flex gap-2">
                 <span className="text-neutral-700 select-none">[14:44:12]</span>
                 <span className="text-purple-500 font-bold uppercase shrink-0">sys:</span>
                 <span className="text-neutral-400">Loading process environment variables... Done (12ms)</span>
               </div>
               <div className="flex gap-2">
                 <span className="text-neutral-700 select-none">[14:44:13]</span>
                 <span className="text-yellow-500 font-bold uppercase shrink-0">warn:</span>
                 <span className="text-neutral-300">No active process attached. Some features have been disabled for safety.</span>
               </div>
               <div className="mt-auto pt-2 border-t border-neutral-800 flex items-center gap-2 group">
                 <span className="text-accent-blue font-bold shrink-0">&gt;</span>
                 <input 
                   placeholder="Type a command (help, attach, scan)..." 
                   className="w-full bg-transparent outline-none text-neutral-200 placeholder:text-neutral-700" 
                 />
               </div>
            </div>
          </div>
        </main>
      </div>

      {/* Global Status Bar */}
      <footer className="h-6 bg-neutral-900 border-t border-neutral-800 flex items-center px-4 justify-between shrink-0 select-none">
        <div className="flex items-center gap-4 text-[10px] font-bold uppercase text-neutral-600">
           <div className="flex items-center gap-1.5 text-accent-blue">
             <Activity size={10} />
             <span>System Ready</span>
           </div>
           <div className="w-[1px] h-3 bg-neutral-800" />
           <div className="flex items-center gap-1.5 hover:text-neutral-400 cursor-pointer transition-colors">
             <Database size={10} />
             <span>Connected to Kernel</span>
           </div>
           <div className="w-[1px] h-3 bg-neutral-800" />
           <div className="flex items-center gap-1.5">
             <List size={10} />
             <span>2,144 Threads</span>
           </div>
        </div>
        
        <div className="flex items-center gap-4 text-[10px] font-bold uppercase text-neutral-600">
          <div className="flex items-center gap-3">
             <span className="hover:text-accent-blue cursor-pointer transition-colors">Ln 1, Col 1</span>
             <span className="hover:text-accent-blue cursor-pointer transition-colors">UTF-8</span>
             <span className="hover:text-accent-blue cursor-pointer transition-colors">Windows (CRLF)</span>
          </div>
          <div className="w-[1px] h-3 bg-neutral-800" />
          <div className="flex items-center gap-1.5 text-neutral-500">
             <HeartPulse size={10} className="text-red-500" />
             <span>72ms Latency</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

