import os
import frida
import typing as t
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()
compile_template = "frida-compile scripts/hooks/{script_name}.ts -o scripts/compiled/{script_name}.js -c"


class RunRequest(BaseModel):
    name: str
    args: list[str]


class RunResponse(BaseModel):
    result: t.Any


@app.get("/")
async def health():
    return "OK"


@app.post("/call", response_model=RunResponse)
async def call_func(request: RunRequest):
    print(f"call func, name: {request.name}, args: {request.args}")
    func = getattr(script.exports_sync, request.name)
    result = func(*request.args)
    print(f"run result: {request.args}")
    return RunResponse(result=result)


@app.get("/list")
async def list_funcs():
    res = {"result": dir(script.exports_sync)}
    return res


if __name__ == "__main__":
    package = ["owasp.mstg.uncrackable1"]
    # script_name = "scripts/test"
    script_name = "test"
    os.system(compile_template.format(script_name=script_name))
    device = frida.get_device_manager().add_remote_device("127.0.0.1:7777")
    pid = device.spawn(package)
    session = device.attach(pid)
    with open("scripts/compiled/" + script_name + ".js", "r", encoding="utf-8") as f:
        script_content = f.read()
    script = session.create_script(script_content)
    script.load()
    print("loaded func: " + str(dir(script.exports_sync)))
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
