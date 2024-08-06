# coding: utf-8
# @author: outlaws-bai
# @date: 2024/08/06 11:03:52
# @description:


def patch_to_camel_case(name: str):
    return name


def patch_frida_rpc_func_name_convert():

    try:
        from frida.core import _to_camel_case

        _to_camel_case.__code__ = patch_to_camel_case.__code__
    except Exception:
        pass
