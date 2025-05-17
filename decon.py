import pyperclip

def decon(st: str):
    st = st.replace(" ", "")
    res = []
    for i in range(0, len(st), 2):
        res.append("0x" + st[i:i+2])
    res = res[::-1]
    lines = []
    for i in range(0, len(res), 8):
        chunk = res[i:i+8]
        lines.append("    " + ", ".join(chunk) + ("," if i + 8 < len(res) else ""))

    output = "{\n" + "\n".join(lines) + "\n},\n"
    print(output, end='')
    pyperclip.copy(output)

try:
    while True:
        whole = ""
        part = input().strip()
        while part != "":
            whole += part
            part = input().strip()
        decon(whole)
except KeyboardInterrupt:
    print("Конец")