import os
import frida
import typing as t
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel
from common import patch_frida_rpc_func_name_convert

patch_frida_rpc_func_name_convert()

app = FastAPI()

compiled_dir = Path.cwd() / "scripts" / "compiled"
if not compiled_dir.exists():
    compiled_dir.mkdir()
compile_template = f"frida-compile scripts/hooks/{{script_name}}.js -o {compiled_dir}/{{script_name}}.js -c"


class RunRequest(BaseModel):
    name: str
    args: t.List[str]


class RunResponse(BaseModel):
    result: t.List | t.Dict


@app.get("/")
async def health():
    return "OK"


@app.post("/call", response_model=RunResponse)
async def call_func(request: RunRequest):
    print(f"call func, name: {request.name}, args: {request.args}")
    func = getattr(script.exports_async, request.name)
    result = await func(*request.args)
    print(f"run result: {request.args}")
    return RunResponse(result=result)


@app.get("/list")
async def list_funcs():
    res = {"result": dir(script.exports_sync)}
    return res


if __name__ == "__main__":
    package = ["owasp.mstg.uncrackable1"]
    frida_conn = "127.0.0.1:7777"
    script_name = "test"

    # compile js
    compile_res = os.system(compile_template.format(script_name=script_name))
    if compile_res != 0:
        exit(f"compile error: {compile_res}")

    # start frida
    device = frida.get_device_manager().add_remote_device(frida_conn)
    pid = device.spawn(package)
    session = device.attach(pid)
    with open("scripts/compiled/" + script_name + ".js", "r", encoding="utf-8") as f:
        script_content = f.read()
    script = session.create_script(script_content)
    script.load()
    print("loaded func: " + str(dir(script.exports_sync)))

    # start web
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
