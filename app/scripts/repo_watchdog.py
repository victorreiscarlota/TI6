#!/usr/bin/env python3
"""
Utilitário para executar um worker em processo separado e impor timeout.
O worker deve escrever seu resultado em JSON no caminho de saída informado.
Esta implementação usa um wrapper top-level para ser compatível com
multiprocessing on Windows (spawn).
"""
import multiprocessing
import json
import os
import traceback

def _worker_wrapper(fn, args_tuple, kwargs_dict, out_path):
    """
    Função top-level executada no processo filho.
    fn deve ser uma função top-level (importável); args_tuple/kwargs_dict devem ser pickláveis.
    Escreve o resultado (ou exceção) em out_path como JSON.
    """
    try:
        if kwargs_dict is None:
            kwargs_dict = {}
        result = fn(*args_tuple, **kwargs_dict)
        if out_path:
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
    except SystemExit:
        raise
    except Exception:
        # Escreve traceback para o pai ler e tratar
        tb = traceback.format_exc()
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump({"__error__": tb}, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

def run_worker_with_timeout(target_fn, args=(), kwargs=None, out_json_path=None, timeout_seconds=1800):
    """
    Executa target_fn(*args, **kwargs) em um processo separado via multiprocessing.Process,
    usando _worker_wrapper (top-level). Retorna (success: bool, result_or_message).

    - success True: result_or_message contém o objeto carregado do out_json_path (ou None se não houver).
    - success False: result_or_message contém a mensagem de erro ou motivo do timeout.
    """
    if kwargs is None:
        kwargs = {}

    # Garantir que target_fn seja um objeto picklável (função top-level). Isso é responsabilidade do chamador.
    p = multiprocessing.Process(target=_worker_wrapper, args=(target_fn, tuple(args), kwargs, out_json_path))
    p.start()
    p.join(timeout_seconds)
    if p.is_alive():
        try:
            p.terminate()
        except Exception:
            pass
        p.join(5)
        return (False, f"timeout after {timeout_seconds} seconds")

    # processo terminou: ler o arquivo de saída, se existir
    if out_json_path and os.path.exists(out_json_path):
        try:
            with open(out_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get("__error__"):
                return (False, f"worker_error: {data.get('__error__')}")
            return (True, data)
        except Exception as e:
            return (False, f"failed to read worker output: {e}")

    return (True, None)