import React, { useRef, useEffect } from 'react';
import { 
  Monitor, 
  Cpu, 
  Search, 
  Activity, 
  Settings, 
  Bell, 
  FolderOpen, 
  Link2, 
  ChevronLeft, 
  ChevronRight,
  Database,
  Type,
  UnfoldHorizontal,
  Code2,
  Terminal,
  Zap,
  X,
  Maximize2,
  Minus,
  Square
} from 'lucide-react';
import { useAppStore, ViewType } from '../store';
import { Button, Input, cn } from '../lib/components';
import { motion, AnimatePresence } from 'motion/react';

/**
 * Custom Title Bar / Top Bar
 */
export const TopBar = () => {
  const attachedProcess = useAppStore(state => state.attachedProcess);
  
  return (
    <div className="h-10 bg-neutral-900 border-bottom border-neutral-800 flex items-center px-3 justify-between drag-region">
      <div className="flex items-center gap-4 flex-1">
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 bg-accent-blue rounded flex items-center justify-center">
            <Zap size={14} className="text-white" />
          </div>
          <span className="font-bold text-neutral-200 tracking-tight">N0x</span>
        </div>
        
        <div className="flex items-center gap-2 text-[11px]">
          <span className="text-neutral-600">/</span>
          <span className={cn("font-medium", attachedProcess ? "text-accent-blue" : "text-neutral-500")}>
            {attachedProcess ? `ATTACHED: ${attachedProcess.name} (${attachedProcess.pid})` : "NO PROCESS ATTACHED"}
          </span>
        </div>
      </div>

      <div className="flex-1 flex justify-center max-w-xl">
        <div className="relative w-full group">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-600 transition-colors group-focus-within:text-neutral-400" />
          <input 
            placeholder="Search processes, symbols, strings (Ctrl+P)..." 
            className="w-full bg-neutral-950/50 border border-neutral-800 rounded px-10 py-1 text-xs text-neutral-300 focus:outline-none focus:border-neutral-700 transition-all placeholder:text-neutral-700"
          />
          <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1">
            <kbd className="px-1 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-[9px] text-neutral-600">⌘</kbd>
            <kbd className="px-1 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-[9px] text-neutral-600">P</kbd>
          </div>
        </div>
      </div>

      <div className="flex-1 flex justify-end items-center gap-2 no-drag-region">
        <div className="flex items-center border-r border-neutral-800 pr-2 mr-2 gap-1">
           <Button variant="ghost" size="icon" className="h-7 w-7"><Bell size={14} /></Button>
           <Button variant="ghost" size="icon" className="h-7 w-7"><Settings size={14} /></Button>
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-7 w-7 hover:bg-neutral-800"><Minus size={14} /></Button>
          <Button variant="ghost" size="icon" className="h-7 w-7 hover:bg-neutral-800"><Square size={12} /></Button>
          <Button variant="ghost" size="icon" className="h-7 w-7 hover:bg-red-500 hover:text-white transition-colors"><X size={14} /></Button>
        </div>
      </div>
    </div>
  );
};

/**
 * Sidebar Navigation
 */
export const Sidebar = () => {
  const { isSidebarCollapsed, setSidebarCollapsed, addTab } = useAppStore();
  
  const navItems: { type: ViewType; icon: any; label: string }[] = [
    { type: 'processes', icon: Activity, label: 'Processes' },
    { type: 'modules', icon: Database, label: 'Modules' },
    { type: 'memory', icon: UnfoldHorizontal, label: 'Hex View' },
    { type: 'strings', icon: Type, label: 'Strings' },
    { type: 'patterns', icon: Search, label: 'Patterns' },
    { type: 'disassembly', icon: Code2, label: 'Disassembly' },
    { type: 'hooks', icon: Link2, label: 'Hooks' },
    { type: 'console', icon: Terminal, label: 'Console' },
  ];

  return (
    <div className={cn(
      "bg-neutral-900 border-r border-neutral-800 transition-all duration-300 flex flex-col group",
      isSidebarCollapsed ? "w-12" : "w-52"
    )}>
      <div className="p-2 border-b border-neutral-800 flex justify-between items-center group-hover:bg-neutral-800/20 transition-colors">
        {!isSidebarCollapsed && <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest pl-1">Navigation</span>}
        <Button 
          variant="ghost" 
          size="icon" 
          onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
          className="h-6 w-6 text-neutral-600 hover:text-neutral-300"
        >
          {isSidebarCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </Button>
      </div>

      <div className="flex-1 py-4 flex flex-col gap-1 px-2">
        {navItems.map((item) => (
          <button
            key={item.type}
            onClick={() => addTab(item.type, item.label)}
            className="flex items-center gap-3 px-2 py-2 rounded text-neutral-400 hover:bg-neutral-800 hover:text-neutral-100 transition-all group/btn"
          >
            <item.icon size={16} className="shrink-0 group-hover/btn:text-accent-blue" />
            {!isSidebarCollapsed && <span className="text-xs font-medium whitespace-nowrap">{item.label}</span>}
          </button>
        ))}
      </div>

      <div className="p-2 border-t border-neutral-800 bg-neutral-950/20">
         <button className="w-full flex items-center gap-3 px-2 py-2 rounded text-neutral-500 hover:text-neutral-200">
           <Cpu size={16} className="shrink-0" />
           {!isSidebarCollapsed && <span className="text-[10px] font-bold uppercase">v1.2.0-STABLE</span>}
         </button>
      </div>
    </div>
  );
};

/**
 * Tabbar component
 */
export const TabBar = () => {
  const { tabs, activeTabId, setActiveTab, removeTab } = useAppStore();

  return (
    <div className="h-9 bg-neutral-900 border-b border-neutral-800 flex items-center overflow-x-auto no-scrollbar">
      {tabs.map((tab) => (
        <div
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className={cn(
            "h-full px-4 flex items-center gap-3 border-r border-neutral-800 cursor-pointer min-w-[120px] max-w-[200px] transition-colors relative group",
            tab.active ? "bg-neutral-950 text-neutral-100" : "bg-neutral-900 text-neutral-500 hover:bg-neutral-800"
          )}
        >
          <span className="text-xs font-medium truncate">{tab.title}</span>
          {tab.active && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent-blue" />}
          
          <button 
            onClick={(e) => {
              e.stopPropagation();
              removeTab(tab.id);
            }}
            className="p-0.5 rounded hover:bg-neutral-700 opacity-0 group-hover:opacity-100 transition-opacity"
          >
            <X size={12} />
          </button>
        </div>
      ))}
    </div>
  );
};
