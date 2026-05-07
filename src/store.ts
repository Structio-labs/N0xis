import { create } from 'zustand';

export type ViewType = 
  | 'processes' 
  | 'modules' 
  | 'memory' 
  | 'strings' 
  | 'patterns' 
  | 'disassembly' 
  | 'hooks' 
  | 'console' 
  | 'settings';

export interface Tab {
  id: string;
  type: ViewType;
  title: string;
  active: boolean;
  params?: any;
}

export interface Process {
  pid: number;
  name: string;
  arch: 'x64' | 'x86';
  cpu: number;
  memory: string;
  threads: number;
  path: string;
  status: 'Running' | 'Suspended' | 'Terminated';
}

interface AppState {
  tabs: Tab[];
  activeTabId: string | null;
  attachedProcess: Process | null;
  isSidebarCollapsed: boolean;
  sidebarWidth: number;
  bottomPanelHeight: number;
  
  // Actions
  addTab: (type: ViewType, title: string, params?: any) => void;
  removeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  attachProcess: (process: Process) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setSidebarWidth: (width: number) => void;
  setBottomPanelHeight: (height: number) => void;
  closeAllTabs: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  tabs: [
    { id: 'initial-processes', type: 'processes', title: 'Process Explorer', active: true }
  ],
  activeTabId: 'initial-processes',
  attachedProcess: null,
  isSidebarCollapsed: false,
  sidebarWidth: 240,
  bottomPanelHeight: 200,

  addTab: (type, title, params) => set((state) => {
    const id = Math.random().toString(36).substr(2, 9);
    const newTab: Tab = { id, type, title, active: true, params };
    return {
      tabs: [...state.tabs.map(t => ({ ...t, active: false })), newTab],
      activeTabId: id
    };
  }),

  removeTab: (id) => set((state) => {
    const newTabs = state.tabs.filter(t => t.id !== id);
    if (newTabs.length === 0) return { tabs: [], activeTabId: null };
    
    let newActiveId = state.activeTabId;
    if (state.activeTabId === id) {
      newActiveId = newTabs[newTabs.length - 1].id;
    }
    
    return {
      tabs: newTabs.map(t => ({ ...t, active: t.id === newActiveId })),
      activeTabId: newActiveId
    };
  }),

  setActiveTab: (id) => set((state) => ({
    tabs: state.tabs.map(t => ({ ...t, active: t.id === id })),
    activeTabId: id
  })),

  attachProcess: (process) => set({ attachedProcess: process }),
  
  setSidebarCollapsed: (isSidebarCollapsed) => set({ isSidebarCollapsed }),
  setSidebarWidth: (sidebarWidth) => set({ sidebarWidth }),
  setBottomPanelHeight: (bottomPanelHeight) => set({ bottomPanelHeight }),
  
  closeAllTabs: () => set({ tabs: [], activeTabId: null })
}));
