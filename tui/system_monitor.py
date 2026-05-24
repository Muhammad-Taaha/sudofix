"""
btop‑style system monitor widget for Textual.
Shows: CPU (overall + per-core bars), RAM, Swap, GPU, Disk (usage + I/O),
       Network (up/down speeds), and active LLM model.

Requirements:
    pip install psutil
    pip install nvidia-ml-py      # optional – NVIDIA GPU
"""

from __future__ import annotations

import os
import time
from collections import deque
from textual.widgets import Static

# ── psutil ───────────────────────────────────────────────────
PSUTIL_OK = False
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    pass

# ── NVIDIA GPU (using nvidia-ml-py) ──
GPU_OK = False
_gpu_handle = None
_gpu_name = ""
try:
    import nvidia_smi as pynvml
    pynvml.nvmlInit()
    _gpu_handle = pynvml.nvmlDeviceGetHandleByIndex(0)
    _raw = pynvml.nvmlDeviceGetName(_gpu_handle)
    _gpu_name = _raw.decode() if isinstance(_raw, bytes) else _raw
    GPU_OK = True
except Exception:
    pass

# ── Drawing constants ────────────────────────────────────────
_SPARK = "▁▂▃▄▅▆▇█"
_FULL = "█"
_EMPTY = "░"


def _col(pct: float) -> str:
    if pct < 50:
        return "green"
    if pct < 80:
        return "yellow"
    return "red"


def _bar(pct: float, width: int = 20, color: str = None) -> str:
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100)
    c = color or _col(pct)
    return (
        f"[{c}]{_FULL * filled}[/{c}]"
        f"[dim]{_EMPTY * (width - filled)}[/dim]"
        f" {pct:5.1f}%"
    )


def _spark_ch(v: float) -> str:
    idx = max(0, min(7, int(v / 100 * 7)))
    return f"[{_col(v)}]{_SPARK[idx]}[/{_col(v)}]"


def _sparkline(vals, width: int = 40) -> str:
    if not vals:
        return "[dim]" + "·" * width + "[/dim]"
    if len(vals) < width:
        step = len(vals) / width
        indices = [int(i * step) for i in range(width)]
        vals = [vals[i] for i in indices]
    else:
        vals = list(vals)[-width:]
    return "".join(_spark_ch(v) for v in vals)


def _hb(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def _speed(s: float) -> str:
    if s < 1024:
        return f"{s:.0f}B/s"
    elif s < 1024*1024:
        return f"{s/1024:.1f}KB/s"
    elif s < 1024*1024*1024:
        return f"{s/(1024*1024):.1f}MB/s"
    else:
        return f"{s/(1024*1024*1024):.1f}GB/s"


class SystemMonitor(Static):
    """Live btop-style resource monitor (refreshes every 1.5s)."""

    DEFAULT_CSS = """
    SystemMonitor {
        height: auto;
        max-height: 40;          /* Enough space for 12+ cores */
        padding: 0 1;
        background: $surface;
        border: solid $primary;
        margin: 1 0;
    }
    """

    def __init__(self, llm_info: dict | None = None, **kw) -> None:
        super().__init__("", **kw)
        self.llm_info = llm_info or {}
        self._cpu_hist = deque(maxlen=60)
        self._net_prev = None
        self._net_ts = 0.0
        self._dio_prev = None
        self._dio_ts = 0.0
        if PSUTIL_OK:
            self._proc = psutil.Process(os.getpid())
        else:
            self._proc = None

    def on_mount(self) -> None:
        self._tick()
        self.set_interval(1.5, self._tick)

    def _tick(self) -> None:
        self.update(self._build())

    def _build(self) -> str:
        if not PSUTIL_OK:
            return "[bold red]psutil not installed[/bold red]\n  pip install psutil"

        lines = []
        # ----- CPU section -----
        cpu_pct = psutil.cpu_percent(interval=0)
        self._cpu_hist.append(cpu_pct)
        n_log = psutil.cpu_count(logical=True) or 1
        n_phy = psutil.cpu_count(logical=False) or n_log
        try:
            freq = psutil.cpu_freq()
            ghz = f" @ {freq.current/1000:.1f}GHz" if freq else ""
        except:
            ghz = ""

        lines.append(
            f"  [bold cyan]CPU[/bold cyan]  {_bar(cpu_pct, 20)}  {n_phy}C/{n_log}T{ghz}")
        lines.append(
            f"  [dim]└─ History[/dim]  {_sparkline(self._cpu_hist, 50)}")

        # per-core bars – one per line (like btop)
        per_core = psutil.cpu_percent(percpu=True)
        for i, p in enumerate(per_core):
            lines.append(f"  [dim]core{i:2d}[/dim] {_bar(p, 12)}")

        # ----- Memory -----
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        lines.append(
            f"  [bold cyan]MEM[/bold cyan]  {_bar(mem.percent, 20)}  {_hb(mem.used)} / {_hb(mem.total)}")
        if swap.total > 0:
            lines.append(f"  [bold cyan]SWAP[/bold cyan] {_bar(swap.percent, 20)}  {
                         _hb(swap.used)} / {_hb(swap.total)}")

        # ----- Disk + I/O -----
        try:
            dk = psutil.disk_usage("/")
            now = time.time()
            dio = psutil.disk_io_counters()
            io_str = ""
            if dio and self._dio_prev and self._dio_ts > 0:
                dt = now - self._dio_ts
                if dt > 0:
                    rd = (dio.read_bytes - self._dio_prev.read_bytes) / dt
                    wr = (dio.write_bytes - self._dio_prev.write_bytes) / dt
                    io_str = f"  [dim]R:[/dim]{_speed(rd)
                                               } [dim]W:[/dim]{_speed(wr)}"
            self._dio_prev, self._dio_ts = dio, now
            lines.append(f"  [bold cyan]DSK[/bold cyan]  {_bar(dk.percent, 20)}  {
                         _hb(dk.used)} / {_hb(dk.total)}{io_str}")
        except Exception:
            pass

        # ----- Network -----
        try:
            now = time.time()
            nc = psutil.net_io_counters()
            if self._net_prev and self._net_ts > 0:
                dt = now - self._net_ts
                if dt > 0:
                    up = (nc.bytes_sent - self._net_prev.bytes_sent) / dt
                    down = (nc.bytes_recv - self._net_prev.bytes_recv) / dt
                    lines.append(
                        f"  [bold cyan]NET[/bold cyan]  ↑ {_speed(up)}  ↓ {_speed(down)}")
            self._net_prev, self._net_ts = nc, now
        except Exception:
            pass

        # ----- GPU -----
        if GPU_OK:
            try:
                util = pynvml.nvmlDeviceGetUtilizationRates(_gpu_handle)
                mem_info = pynvml.nvmlDeviceGetMemoryInfo(_gpu_handle)
                vram_percent = (mem_info.used / mem_info.total) * \
                    100 if mem_info.total else 0
                try:
                    temp = pynvml.nvmlDeviceGetTemperature(
                        _gpu_handle, pynvml.NVML_TEMPERATURE_GPU)
                    temp_str = f"  [dim]{temp}°C[/dim]"
                except:
                    temp_str = ""
                lines.append(
                    f"  [bold cyan]GPU[/bold cyan]  {_bar(util.gpu, 20)}  {_gpu_name}{temp_str}")
                lines.append(f"  [bold cyan]VRAM[/bold cyan] {_bar(vram_percent, 20)}  {
                             _hb(mem_info.used)} / {_hb(mem_info.total)}")
            except Exception:
                lines.append("  [bold cyan]GPU[/bold cyan]  [dim]error[/dim]")

        # ----- Current process (this TUI) -----
        if self._proc:
            try:
                mem_rss = self._proc.memory_info().rss
                cpu_proc = self._proc.cpu_percent(interval=0)
                threads = self._proc.num_threads()
                lines.append(f"  [bold cyan]PROC[/bold cyan]  RSS: {
                             _hb(mem_rss)}  CPU: {cpu_proc:.1f}%  Threads: {threads}")
            except:
                pass

        # ----- LLM model -----
        mdl = self.llm_info.get("model", "n/a")
        prov = self.llm_info.get("provider", "")
        src = self.llm_info.get("source", "")
        lines.append(
            f"  [bold magenta]🤖 LLM[/bold magenta]  {mdl} [dim]({prov} • {src})[/dim]")

        return "\n".join(lines)
