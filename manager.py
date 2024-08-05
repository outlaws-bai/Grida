import frida
import typing as t
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()


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
    func = getattr(script.exports_sync, request.name)
    print(func)
    print(func(*request.args))
    return RunResponse(result=func(*request.args))


@app.get("/list")
async def list_funcs():
    res = {"result": dir(script.exports_sync)}
    print(res)
    return res


if __name__ == "__main__":
    package = ["owasp.mstg.uncrackable1"]
    script_name = "test"
    device = frida.get_device_manager().add_remote_device("127.0.0.1:7777")
    pid = device.spawn(package)
    session = device.attach(pid)
    with open("hooks/" + script_name + ".js", "r", encoding="utf-8") as f:
        script_content = f.read()
    script = session.create_script(script_content)
    script.load()
    print("loaded func: " + str(dir(script.exports_sync)))
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
