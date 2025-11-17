#!/usr/bin/env python3
"""
Watchdog via subprocess: executa um callable em processo Python separado,
impõe timeout e lê o resultado de um arquivo JSON. Compatível com Windows.
Agora injeta o diretório do projeto em sys.path do runner para resolver 'app'.
"""
import subprocess
import sys
import os
import json
import textwrap
import time

PYTHON_EXEC = sys.executable

def run_callable_in_subprocess(module_name: str,
                               func_name: str,
                               args: list,
                               out_json_path: str,
                               timeout_seconds: int):
    """
    Executa module_name.func_name(*args) em subprocess.
    A função deve escrever o JSON final em out_json_path (o wrapper também grava se a função retornar valor).
    Retorna (success: bool, data_or_message: object|str).
    """
    os.makedirs(os.path.dirname(out_json_path) or ".", exist_ok=True)

    # Diretório do projeto (raiz atual do processo pai)
    project_root = os.getcwd()

    wrapper_code = textwrap.dedent(f"""
    import json, sys, os, traceback
    # garante que o pacote 'app' seja importável no subprocesso
    sys.path.insert(0, {project_root!r})
    try:
        from {module_name} import {func_name}
        res = {func_name}(*{repr(args)})
        if res is not None:
            with open({out_json_path!r}, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2, ensure_ascii=False)
    except Exception:
        tb = traceback.format_exc()
        with open({out_json_path!r}, "w", encoding="utf-8") as f:
            json.dump({{"__error__": tb}}, f, indent=2, ensure_ascii=False)
    """)
    tmp_wrapper = out_json_path + ".runner.py"
    with open(tmp_wrapper, "w", encoding="utf-8") as f:
        f.write(wrapper_code)

    start = time.time()
    proc = subprocess.Popen([PYTHON_EXEC, tmp_wrapper],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            encoding="utf-8",
                            errors="replace")
    try:
        while True:
            ret = proc.poll()
            if ret is not None:
                break
            if (time.time() - start) > timeout_seconds:
                try:
                    proc.terminate()
                except Exception:
                    pass
                time.sleep(1)
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return (False, f"timeout after {timeout_seconds} seconds")
            time.sleep(0.5)

        stdout, stderr = proc.communicate()
        if os.path.exists(out_json_path):
            try:
                with open(out_json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and data.get("__error__"):
                    return (False, f"worker_error: {data['__error__']}")
                return (True, data)
            except Exception as e:
                return (False, f"failed to read worker output: {e}")
        if ret == 0:
            return (True, None)
        return (False, f"process exited code {ret}; stderr: {stderr[:500]}")
    finally:
        try:
            os.remove(tmp_wrapper)
        except Exception:
            pass