from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import binascii

from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["DEBUG"] = True

X86_CODE32 = b"\x41\x4a"

ADDRESS = 0x1000000


def get_instruction_string(instr):
    strg = ''
    for i in instr:
        strg += i + '; '
    return strg


def convert_hex_list(hex_list):
    hex = []
    for x in range(len(hex_list)):
        hex.append(binascii.unhexlify(hex_list[x]))
    return hex


def print_hex(hex):
    for x in range(len(hex)):
        print("{0:b}".format(ord(binascii.unhexlify(hex[x]))).zfill(8))


def execute(CODE):
    print("Emulate i386 code")
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        mu.mem_write(ADDRESS, CODE)
        mu.reg_write(UC_ARCH_X86, 0x1234)
        mu.reg_write(UC_ARCH_X86, 0x7890)
        # emulate code in infinite time & unlimited instructions
        mu.emu_start(ADDRESS, ADDRESS + len(CODE))
        # now print out some registers
        print("Emulation done. Below is the CPU context")
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        print(">>> ECX = 0x%x" % r_ecx)
        print(">>> EDX = 0x%x" % r_edx)

    except UcError as e:
        print("Error: %s" % e)


@app.route('/api/', methods=['GET'])
def api():
    content = request.get_json()
    architecture = content['architecture']
    mode = content['mode']
    instructions = content['instructions']
    binary = content['binary']
    hex = content['hex']
    hex_string = content['hex_string']

    print("Architecture: " + architecture)
    print("Mode: " + mode)
    print("Instructions: ")
    for x in range(len(instructions)):
        print(instructions[x])
    print("Binary: ")
    for x in range(len(binary)):
        print(binary[x])
    print("Hex: ")
    for x in range(len(hex)):
        print(hex[x])
    print("Hex String: " + hex_string)

    # hex0 = re.sub(r'[^\w]', '', hex[0])
    # hex_value = int(hex0, 16)
    # bin_val = binascii.unhexlify(hex0)
    # print("Binary value of hex at 0: " + bin_val)
    print_hex(hex)
    hex_list = convert_hex_list(hex)
    print(hex_list)
    # by1 = bytes(hex_list)
    hex_data = binascii.unhexlify(hex_string)
    execute(hex_data)

    return jsonify(content)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

