import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

type ProcessStatus = 'Running' | 'Suspended' | 'Terminated';
type Arch = 'x64' | 'x86';

interface ProcessInfo {
  pid: number;
  name: string;
  arch: Arch;
  cpu: number;
  memoryMB: number;
  threads: number;
  path: string;
  status: ProcessStatus;
}

const views = ['processes', 'memory', 'disassembly', 'console'] as const;
type View = (typeof views)[number];

const c = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  gray: '\x1b[38;5;245m',
  white: '\x1b[97m',
  blue: '\x1b[38;5;39m',
  green: '\x1b[38;5;48m',
  yellow: '\x1b[38;5;220m',
  red: '\x1b[38;5;203m',
  bg: '\x1b[48;5;235m',
};

const names = [
  'explorer.exe',
  'chrome.exe',
  'svchost.exe',
  'discord.exe',
  'steam.exe',
  'code.exe',
  'cmd.exe',
  'taskmgr.exe',
];

const processes: ProcessInfo[] = Array.from({ length: 250 }, (_, i) => {
  const name = names[Math.floor(Math.random() * names.length)];
  return {
    pid: 1000 + i,
    name,
    arch: Math.random() > 0.3 ? 'x64' : 'x86',
    cpu: Number((Math.random() * 11).toFixed(1)),
    memoryMB: Number((Math.random() * 950 + 20).toFixed(1)),
    threads: Math.floor(Math.random() * 60) + 1,
    path: `C:\\Windows\\System32\\${name}`,
    status: Math.random() > 0.92 ? 'Suspended' : 'Running',
  };
});

const hexMemory = new Uint8Array(4096).map(() => Math.floor(Math.random() * 256));
const disassembly = [
  { addr: '004012A0', bytes: '55 8B EC', asm: 'push ebp; mov ebp, esp' },
  { addr: '004012A3', bytes: '83 EC 10', asm: 'sub esp, 0x10' },
  { addr: '004012A6', bytes: '8B 45 08', asm: 'mov eax, [ebp+0x08]' },
  { addr: '004012A9', bytes: '85 C0', asm: 'test eax, eax' },
  { addr: '004012AB', bytes: '74 05', asm: 'je 0x004012B2' },
  { addr: '004012AD', bytes: 'FF 50 04', asm: 'call dword ptr [eax+0x04]' },
  { addr: '004012B0', bytes: '33 C0', asm: 'xor eax, eax' },
  { addr: '004012B2', bytes: '8B E5 5D C3', asm: 'mov esp, ebp; pop ebp; ret' },
];

let activeView: View = 'processes';
let attachedProcess: ProcessInfo | null = null;
let filter = '';
let selectedPid: number | null = null;

function paint(text: string, color: string) {
  return `${color}${text}${c.reset}`;
}

function hr(char = '─', width = 90) {
  return char.repeat(width);
}

function renderHeader() {
  const mode = attachedProcess ? `${attachedProcess.name} (${attachedProcess.pid})` : 'No process attached';
  const status = attachedProcess ? paint('READY', c.green) : paint('IDLE', c.yellow);
  console.clear();
  console.log(paint(` ${hr('═', 90)} `, c.gray));
  console.log(
    `${paint(' N0x CLI ', c.bg + c.white)} ${paint('Swiss/Modern reverse engineering workspace', c.gray)}`
  );
  console.log(`${paint(' View:', c.gray)} ${paint(activeView.toUpperCase(), c.blue)}   ${paint(' Target:', c.gray)} ${mode}`);
  console.log(`${paint(' Status:', c.gray)} ${status}`);
  console.log(paint(` ${hr('═', 90)} `, c.gray));
}

function formatProcessRow(p: ProcessInfo) {
  const statusColor = p.status === 'Running' ? c.green : p.status === 'Suspended' ? c.yellow : c.red;
  const selected = selectedPid === p.pid ? paint('>', c.blue) : ' ';
  return `${selected} ${String(p.pid).padEnd(6)} ${p.name.padEnd(14)} ${p.arch.padEnd(3)} ${String(p.cpu).padStart(4)}% ${String(
    p.memoryMB.toFixed(1),
  ).padStart(8)} MB ${String(p.threads).padStart(3)} th ${paint(p.status.padEnd(9), statusColor)} ${paint(p.path, c.dim + c.gray)}`;
}

function renderProcesses() {
  const list = processes.filter((p) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return p.name.toLowerCase().includes(q) || String(p.pid).includes(q) || p.path.toLowerCase().includes(q);
  });

  console.log(paint(' PID    NAME           ARC CPU     MEMORY  THREADS STATUS    PATH', c.gray));
  console.log(paint(hr('─', 90), c.gray));
  list.slice(0, 20).forEach((p) => console.log(formatProcessRow(p)));
  console.log(paint(hr('─', 90), c.gray));
  console.log(`${paint('Rows:', c.gray)} ${list.length} ${paint('|', c.gray)} ${paint('Filter:', c.gray)} ${filter || '(none)'}`);
}

function renderHex(offset = 0) {
  const safeOffset = Math.max(0, Math.min(hexMemory.length - 16, offset));
  console.log(paint(' Address    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII', c.gray));
  console.log(paint(hr('─', 90), c.gray));
  for (let row = 0; row < 16; row++) {
    const base = safeOffset + row * 16;
    const slice = hexMemory.slice(base, base + 16);
    const bytes = Array.from(slice)
      .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
      .join(' ');
    const ascii = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    console.log(`${paint(base.toString(16).toUpperCase().padStart(8, '0'), c.blue)}   ${bytes}  ${paint(ascii, c.gray)}`);
  }
}

function renderDisassembly() {
  console.log(paint(' ADDRESS   BYTES            INSTRUCTION', c.gray));
  console.log(paint(hr('─', 90), c.gray));
  disassembly.forEach((line) => {
    console.log(`${paint(line.addr, c.blue)}  ${paint(line.bytes.padEnd(15), c.gray)} ${paint(line.asm, c.white)}`);
  });
}

function renderConsoleHelp() {
  console.log(paint(' COMMANDS', c.gray));
  console.log(paint(hr('─', 90), c.gray));
  console.log(' help                         show this help');
  console.log(' view <processes|memory|disassembly|console>');
  console.log(' search <query>               filter process list');
  console.log(' select <pid>                 choose process row');
  console.log(' attach <pid>                 attach target process');
  console.log(' hex <offset-decimal>         jump to memory offset');
  console.log(' disasm                       print disassembly block');
  console.log(' clear                        clear terminal');
  console.log(' exit                         quit');
}

function parseIntSafe(value?: string) {
  if (!value) return null;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : null;
}

function handleCommand(raw: string): boolean {
  const [cmd, ...rest] = raw.trim().split(/\s+/);
  if (!cmd) return true;

  switch (cmd.toLowerCase()) {
    case 'help':
      renderConsoleHelp();
      return true;
    case 'view': {
      const target = rest[0] as View | undefined;
      if (!target || !views.includes(target)) {
        console.log(paint('Invalid view. Use: processes | memory | disassembly | console', c.red));
        return true;
      }
      activeView = target;
      return true;
    }
    case 'search':
      filter = rest.join(' ').trim();
      activeView = 'processes';
      return true;
    case 'select': {
      const pid = parseIntSafe(rest[0]);
      if (!pid) {
        console.log(paint('Usage: select <pid>', c.red));
        return true;
      }
      const found = processes.find((p) => p.pid === pid);
      if (!found) {
        console.log(paint(`PID ${pid} not found`, c.red));
        return true;
      }
      selectedPid = pid;
      console.log(paint(`Selected PID ${pid} (${found.name})`, c.blue));
      return true;
    }
    case 'attach': {
      const pid = parseIntSafe(rest[0]) ?? selectedPid;
      if (!pid) {
        console.log(paint('Usage: attach <pid>  (or select first)', c.red));
        return true;
      }
      const found = processes.find((p) => p.pid === pid);
      if (!found) {
        console.log(paint(`PID ${pid} not found`, c.red));
        return true;
      }
      attachedProcess = found;
      console.log(paint(`Attached: ${found.name} (${found.pid})`, c.green));
      return true;
    }
    case 'hex': {
      const offset = parseIntSafe(rest[0]);
      activeView = 'memory';
      renderHeader();
      renderHex(offset ?? 0);
      return true;
    }
    case 'disasm':
      activeView = 'disassembly';
      return true;
    case 'clear':
      console.clear();
      return true;
    case 'exit':
    case 'quit':
      return false;
    default:
      console.log(paint(`Unknown command: ${cmd}. Type "help".`, c.red));
      return true;
  }
}

async function run() {
  const rl = readline.createInterface({ input, output });
  renderHeader();
  renderProcesses();
  renderConsoleHelp();

  let running = true;
  while (running) {
    const command = await rl.question(paint('\n n0x> ', c.blue));
    running = handleCommand(command);
    if (!running) break;

    renderHeader();
    switch (activeView) {
      case 'processes':
        renderProcesses();
        break;
      case 'memory':
        renderHex();
        break;
      case 'disassembly':
        renderDisassembly();
        break;
      case 'console':
        renderConsoleHelp();
        break;
    }
  }

  rl.close();
  console.log(paint('\nSession ended.', c.gray));
}

run().catch((error: unknown) => {
  console.error(paint(`Fatal error: ${String(error)}`, c.red));
  process.exitCode = 1;
});
