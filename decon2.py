import pyperclip

def decon2(st: str):
    chars = [f"'{c}'" for c in st]
    lines = []
    for i in range(0, len(chars), 8):
        chunk = chars[i:i+8]
        lines.append("    " + ", ".join(chunk) + ("," if i + 8 < len(chars) else ""))
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
        decon2(whole)
except KeyboardInterrupt:
    print("Конец")
