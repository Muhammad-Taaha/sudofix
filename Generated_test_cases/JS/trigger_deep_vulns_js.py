#!/usr/bin/env python3
import subprocess
import tempfile
import os
import sys
import json
import time
import threading
import urllib.request
import shutil

def run_engine(cmd, timeout=10):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)

def test_overflow(binary):
    print("[*] Testing VULN-1: integer overflow in allocBuffer")
    config = {
        "port": 18080,
        "jobs": [{
            "type": "transform",
            "pattern": "A" * 100,
            "multiplier": 9007199254740992  # Number.MAX_SAFE_INTEGER + 1
        }]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    try:
        ret, out, err = run_engine(["node", binary, config_path], timeout=5)
        if ret != 0 and ret != -1:
            print("    VULN-1 triggered (crash)")
            return True
        else:
            print("    VULN-1 not triggered")
            return False
    finally:
        os.unlink(config_path)

def test_uaf(binary):
    print("[*] Testing VULN-2: use-after-free (dangling resource)")
    # In JS, this is simulated by double-free in processFiles, so we test that instead.
    # We'll skip for now and let the processFiles test cover double close.
    return False

def test_path_traversal(binary):
    print("[*] Testing VULN-3: path traversal via symlink following")
    base = tempfile.mkdtemp()
    target_file = os.path.join(base, "target.txt")
    with open(target_file, 'w') as f:
        f.write("do not delete me")
    inner_dir = os.path.join(base, "inner")
    os.mkdir(inner_dir)
    symlink_path = os.path.join(inner_dir, "link_to_target")
    os.symlink(target_file, symlink_path)
    config = {
        "port": 18082,
        "jobs": [{
            "type": "cleanup_dir",
            "dir": inner_dir
        }]
    }
    config_path = os.path.join(base, "config.json")
    with open(config_path, 'w') as f:
        json.dump(config, f)
    try:
        ret, out, err = run_engine(["node", binary, config_path], timeout=5)
        if not os.path.exists(target_file):
            print("    VULN-3 triggered (target file deleted)")
            return True
        else:
            print("    VULN-3 not triggered")
            return False
    finally:
        shutil.rmtree(base, ignore_errors=True)

def test_race(binary):
    print("[*] Testing VULN-4: race condition on memory pool")
    config = {
        "port": 18083,
        "jobs": [{
            "type": "transform",
            "pattern": "race",
            "multiplier": 1
        }] * 500
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    engine_proc = None
    try:
        engine_proc = subprocess.Popen(["node", binary, config_path],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        def hammer():
            for _ in range(50):
                try:
                    urllib.request.urlopen("http://127.0.0.1:18083/status", timeout=1)
                except:
                    pass
        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        time.sleep(2)
        ret = engine_proc.poll()
        if ret is None:
            engine_proc.terminate()
            engine_proc.wait(timeout=2)
            print("    VULN-4 not triggered (no crash)")
            return False
        else:
            print("    VULN-4 triggered (crash during concurrent access)")
            return True
    finally:
        if engine_proc and engine_proc.poll() is None:
            engine_proc.kill()
        os.unlink(config_path)

def test_command_injection(binary):
    print("[*] Testing VULN-5: command injection")
    marker = "/tmp/vuln5_injected_" + str(os.getpid())
    config = {
        "port": 18084,
        "jobs": [{
            "type": "pipeline",
            "cmd": f"echo injected > {marker}",
            "pattern": ""
        }]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    try:
        ret, out, err = run_engine(["node", binary, config_path], timeout=5)
        if os.path.exists(marker):
            print("    VULN-5 triggered (file created)")
            os.unlink(marker)
            return True
        else:
            print("    VULN-5 not triggered")
            return False
    finally:
        os.unlink(config_path)

def test_double_free(binary):
    print("[*] Testing VULN-6: double close file descriptor")
    valid = tempfile.mkstemp()[1]
    config = {
        "port": 18085,
        "jobs": [{
            "type": "process_files",
            "file1": valid,
            "file2": "/nonexistent_file_x"
        }]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    try:
        ret, out, err = run_engine(["node", binary, config_path], timeout=5)
        if ret != 0 and ret != -1:
            print("    VULN-6 triggered (crash)")
            return True
        else:
            print("    VULN-6 not triggered")
            return False
    finally:
        os.unlink(config_path)
        if os.path.exists(valid):
            os.unlink(valid)

def test_info_leak(binary):
    print("[*] Testing info leak (Buffer.allocUnsafe)")
    config = {
        "port": 18086,
        "jobs": [{"type": "log_leak"}]
    }
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        config_path = f.name
    leak_file = "leak_log.bin"
    if os.path.exists(leak_file):
        os.unlink(leak_file)
    try:
        ret, out, err = run_engine(["node", binary, config_path], timeout=5)
        if os.path.exists(leak_file):
            with open(leak_file, 'rb') as f:
                data = f.read()
            # allocUnsafe may contain non-zero data; check if any byte beyond the written part is non-zero
            # Written part: first 4 bytes (level) + 'sensitive data' length (14) = 18 bytes
            if len(data) > 18 and any(b != 0 for b in data[18:]):
                print("    Info leak triggered (uninitialized bytes found)")
                os.unlink(leak_file)
                return True
            else:
                print("    Info leak not detected")
                os.unlink(leak_file)
                return False
        else:
            print("    leak_log.bin not created")
            return False
    finally:
        os.unlink(config_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <app.js path>")
        sys.exit(1)
    appjs = sys.argv[1]
    if not os.path.isfile(appjs):
        print("app.js not found")
        sys.exit(1)
    results = {}
    results['VULN-1'] = test_overflow(appjs)
    results['VULN-2'] = False  # Placeholder (UAF not easily demonstrable in JS)
    results['VULN-3'] = test_path_traversal(appjs)
    results['VULN-4'] = test_race(appjs)
    results['VULN-5'] = test_command_injection(appjs)
    results['VULN-6'] = test_double_free(appjs)
    results['INFO-LEAK'] = test_info_leak(appjs)
    print("\nResults:")
    for k, v in results.items():
        status = "TRIGGERED" if v else "NOT TRIGGERED"
        print(f"  {k}: {status}")