while True:
    A = ""
    part = input().strip()
    while part != "":
        A += part
        part = input().strip()

    print("Конец ввода A.")
    A = bytes.fromhex(A)[::-1]

    B = ""
    part = input().strip()
    while part != "":
        B += part
        part = input().strip()

    print("Конец ввода B.")
    B = bytes.fromhex(B)

    if A == B: print("Сопадают.")
    else:
        for i, (a, b) in enumerate(zip(A,B)):
            if a != b: print(i, a, b)