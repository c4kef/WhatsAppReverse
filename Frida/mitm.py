from mitmproxy import http
from mitmproxy import ctx

def request(flow: http.HTTPFlow) -> None:
    if flow.request.url == "1https://v.whatsapp.net/v2/code":
        ctx.log.info("Sensitive pattern found")
        flow.kill()
        ctx.log.info("Am I killed part 1")