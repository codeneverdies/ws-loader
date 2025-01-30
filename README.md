# ws-loader

> **ws-loader works as a staged loader for 64 bit windows operating systems communicating over websockets.**

# Features

+ `Windows API Hashing`

+ Custom versions of `GetProcAddress` and `GetModuleHandle`

+ `Automatically` determines the payload type when payload is sent

+ `System Proxy` aware

+ Reflectively load PEs

+ Load `Sliver C2` beacons ( `--format exe, dll, bin` )

+ Load `Havoc C2` beacons ( `exe, bin` )

+ `Shellcode execution through windows callbacks`

    1. `EnumPwrSchemes`

    2. `EnumUILanguagesA`

    3. `EnumSystemCodePagesA`

+ `Anti-Debugging`

    1. Check if process was started by debugger ( `NtGlobalFlag` )

+ `Anti-Sandbox`

    1. Time based ( `QueryPerformanceCounter` )

+ `Execution Guard rails`

    1. Check if hostname djb2 hash matches target ( `djb2(GetComputerNameA)` )
    
    2. Check for running enemy processes ( `Ex: Wireshark, x64dbg` )

# DISCLAIMER

> **This will not run "out of the box" you will need to**

1. Change `WSL_TARGET` in `anti.h` by running `./scripts/dj 'YOUR TARGET HOSTNAME'`

2. Change `WSL_SLEEP_TIME`

3. Change the `home` variable in the `wsl_get_ws` function to the ip address of where you run the websocket server


> **THIS PROGRAM SHOULD NOT BE USED FOR MALICIOUS PURPOSES THIS TOOL WAS NOT CREATED FOR MALICOUS INTENT THIS REPOSITORY SHOULD ONLY BE USED TO LEARN READ THE CODE**

# Srv

> **I also wrote a small websocket server in `srv` while testing to serve a payload**

### Install poetry if needed

+ `sudo apt install pipx`
+ `pipx install poetry`

### Run server

+ `cd srv/`
+ `poetry install`
+ `poetry run python3 -B main.py -i [IP] -p [PORT] -b [PAYLOAD]`
> **-B Flag don't write .pyc files on import**

# References

## WebSocket (WinHttp) API

+ [Example from msdn](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/WinhttpWebsocket/cpp/WinhttpWebsocket.cpp)

+ [You can also go here and CTRL+F on Websocket](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/)

## Loader related

+ [Kyle's TitanLdr](https://github.com/kyleavery/TitanLdr)

+ [5pider's KaynLdr](https://github.com/Cracked5pider/KaynLdr)

+ [boku7's BokuLoader](https://github.com/boku7/BokuLoader)

+ [Aaron Bray's writing-a-windows-loader](https://www.ambray.dev/writing-a-windows-loader/)

+ [PE format PDF](https://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)

+ [This entire blog is wonderful I constantly reference it](https://pre.empt.blog/2023/maelstrom-4-writing-a-c2-implant)


## Anti-* related

+ [al-khaser repo has all sorts of anti debugging techniques](https://github.com/ayoubfaouzi/al-khaser)

+ [Check Point Research's awesome website -  Anti-Debug Tricks ](https://anti-debug.checkpoint.com/)

## Shellcode execution related

+ [ropgadget - Abusing native Windows functions for shellcode execution](http://ropgadget.com/posts/abusing_win_functions.html)

+ [MORPHISEC LAB - Fileless Malware: Attack Trend Exposed](https://engage.morphisec.com/hubfs/wp-content/uploads/2017/11/Fileless-Malware_Attack-Trend-Exposed.pdf)

+ [https://github.com/aahmad097/AlternativeShellcodeExec](https://github.com/aahmad097/AlternativeShellcodeExec)

## Hashing related

[https://theartincode.stanis.me/008-djb2/](https://theartincode.stanis.me/008-djb2/)

---

## Back story

> **While I was playing `Wutai` the Red Team lab on [Vulnlab](https://www.vulnlab.com/) by xct, I guess at the time I was playing the loader in the video was already flagged by Avira (Still not sure at this point) since I couldn't get that to work I wrote my own loader and tried to incorporate everything I would need in terms of getting a beacon. It isn't the greatest, it is NOT bypassing any hooks but it gets the job done that's for sure.**

> **This is just a mashup of things I found useful it is NOT supposed to be fancy BUT There are two reasons why I chose to use websockets**

+ **On Wutai the client computers have an outbound system proxy `(squidproxy)`. Meaning all communication will be through that proxy using HTTP, perfect for our websockets that initiate the conversation using HTTP and switch to raw TCP connection.**

+ **`ws-loader` works as a staged loader so I needed some way that abides by the rules of the environment to send what I wanted to execute**