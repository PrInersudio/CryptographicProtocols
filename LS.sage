Lcoeffs = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

Sbox = [
    252, 238, 221,  17, 207, 110,  49,  22, 251, 196, 250, 218,  35, 197,   4,  77,
    233, 119, 240, 219, 147,  46, 153, 186,  23,  54, 241, 187,  20, 205,  95, 193,
    249,  24, 101,  90, 226,  92, 239,  33, 129,  28,  60,  66, 139,   1, 142,  79,
      5, 132,   2, 174, 227, 106, 143, 160,   6,  11, 237, 152, 127, 212, 211,  31,
    235,  52,  44,  81, 234, 200,  72, 171, 242,  42, 104, 162, 253,  58, 206, 204,
    181, 112,  14,  86,   8,  12, 118,  18, 191, 114,  19,  71, 156, 183,  93, 135,
     21, 161, 150,  41,  16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
     50, 117,  25,  61, 255,  53, 138, 126, 109,  84, 198, 128, 195, 189,  13,  87,
    223, 245,  36, 169,  62, 168,  67, 201, 215, 121, 214, 246, 124,  34, 185,   3,
    224,  15, 236, 222, 122, 148, 176, 188, 220, 232,  40,  80,  78,  51,  10,  74,
    167, 151,  96, 115,  30,   0,  98,  68,  26, 184,  56, 130, 100, 159,  38,  65,
    173,  69,  70, 146,  39,  94,  85,  47, 140, 163, 165, 125, 105, 213, 149,  59,
      7,  88, 179,  64, 134, 172,  29, 247,  48,  55, 107, 228, 136, 217, 231, 137,
    225,  27, 131,  73,  76,  63, 248, 254, 141,  83, 170, 144, 202, 216, 133,  97,
     32, 113, 103, 164,  45,  43,   9,  91, 203, 155,  37, 208, 190, 229, 108,  82,
     89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,  57,  75,  99, 182
]

GF2polies.<x> = GF(2)[]
irreducible = x^8 + x^7 + x^6 + x + 1

GF256.<x> = GF(256, name = 'x', modulus = irreducible)

int_to_element = lambda n: GF256(sum(((n >> i) & 1) * x^i for i in range(8)))
element_to_int = lambda element: sum(int(element.polynomial().coefficient(i)) << i for i in range(8))
list_to_mat = lambda lst: Matrix(GF256, [[int_to_element(n) for n in row] for row in lst])
matrix_to_list = lambda mat: [[element_to_int(mat[i][j]) for j in range(mat.ncols())] for i in range(mat.nrows())]

def print_list(lst):
    for row in lst:
        print(', '.join(f"{el:>3}" for el in row))
    print()

Lmatrix = [Lcoeffs]
for i in range(15):
    Lmatrix.append([0] * i + [1] + [0] * (15 - i))
print_list(Lmatrix)
Lmatrix = list_to_mat(Lmatrix)

Lmatrix16 = Lmatrix^16
print_list(matrix_to_list(Lmatrix16))
Sbox = [int_to_element(n) for n in Sbox]

LS = []
for i in range(16):
    Li = []
    for b in range(256):
        Lib = []
        for j in range(16):
            Lib.append(element_to_int(Lmatrix16[j][i] * Sbox[b]))
        Li.append(Lib)
    LS.append(Li)

print(LS[0][2])
print(LS[0][3])

def format_ls_hex_cpp(LS):
    lines = []
    lines.append("#ifndef LSPRECOMPILED_HPP")
    lines.append("#define LSPRECOMPILED_HPP")
    lines.append("")
    lines.append("inline constexpr uint8_t LS[16][256][16] = {")
    for i, Li in enumerate(LS):
        lines.append("  {")  # начало блока 256 строк
        for b, Lib in enumerate(Li):
            hex_bytes = ', '.join(f"0x{val:02X}" for val in Lib)
            lines.append(f"    {{ {hex_bytes} }},")
        lines.append("  },")
    lines.append("};")
    lines.append("#endif")
    return '\n'.join(lines)

with open("Sources/LSPrecompiled.hpp", "w") as f:
    print(format_ls_hex_cpp(LS), file = f)