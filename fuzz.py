from qiling.const import QL_VERBOSE
from qiling import *
import sys
import random
from qiling.extensions.coverage import utils as cov_utils
import secrets
import os
import glob

def get_bytes(filename):
	f = open(filename, "rb").read()
	return bytearray(f)

def magic(data):
    magic_vals = [(1, [0x0]),
            (1, [0x7f]),
            (1, [0x80]),
            (1, [0xff]),
            (2, [0x0, 0x0]),
            (2, [0x7f, 0xff]),
            (2, [0x80, 0x00]),
            (2, [0xff, 0xff]),
            (4, [0x0, 0x0, 0x0, 0x0]),
            (4, [0x7f, 0xff, 0xff, 0xff]),
            (4, [0x80, 0x00, 0x00, 0x00]),
            (4, [0xff, 0xff, 0xff, 0xff])]
    choice = random.choice(magic_vals)
    length = len(data) - 8
    index = range(0, length)
    picked_index = random.choice(index)
    for i in range(choice[0]):
        data[picked_index+i] = choice[1][i]
    return data
    

def mutate_file(input_file, mutated_input):
    mutated_file = os.path.join('rootfs/tmp/', os.path.basename(input_file))
    with open(mutated_file, "wb") as f:
        f.write(mutated_input)

def flip_bit(byte_array, index):
    """Flips the bit at the given index in the byte array"""
    byte_index = index // 8
    bit_index = index % 8
    byte_array[byte_index] ^= 1 << bit_index
    return byte_array

def flipping(data):
    num_of_flips = int((len(data) - 4) * .01)
    indexes = range(4, (len(data) - 4))
    chosen_indexes = []
    counter = 0
    while counter < num_of_flips:
        chosen_indexes.append(random.choice(indexes))
        counter += 1
    for i in chosen_indexes:
        data = flip_bit(data,i)
    return data

def mutator(data):
    option = [0,1]
    picked_mutation = random.choice(option)
    if picked_mutation == 0:
        #1
        data = flipping(data)
    elif picked_mutation == 1:
        #2
        data = magic(data)
    

def by_pass_isa_check(ql: Qiling) -> None:
    print("by_pass_isa_check():")
    ql.arch.regs.rip += 0x15
    pass

def dump(ql, *args, **kw):
    ql.save(reg=False, cpu_context=True, snapshot="snapshot.bin")
    ql.emu_stop()

def callback(ql, address, size):
    coverage.add(address)

def update_coverage(input_file, mutated_input):
    if len(coverage - all_coverage) > 0:
        mutated_file = os.path.join(corpus_path, os.path.basename(input_file[:-4] + secrets.token_hex(16) + input_file[-4:]))
        with open(mutated_file, "wb") as f:
            f.write(mutated_input)
        all_coverage.update(coverage)

def crash_handler(ql, address):
    print("Program crashed at address 0x%x" % address)
    ql.save("snapshots/crash-" + secrets.token_hex(16) + ".snapshot")
    ql.emu_stop()

def exception_hook(ql, address):
    exception_type, exception_value, traceback = ql.exc_info()
    print("Exception: %s" % exception_type)
    ql.save("rootfs/snapshots/crash-" + exception_type + "-" + secrets.token_hex(16) + ".snapshot")
    ql.emu_stop()

def harness():
    input_file = random.choice(corpus)
    data = get_bytes(input_file)
    mutator(data)
    mutate_file(input_file, data)
    ql = Qiling([cmd, "tmp/" + input_file, "-verbose"], rootfs_path, verbose=QL_VERBOSE.OFF)
    ql.hook_block(callback)
    ql.add_fs_mapper('/proc', '/proc')
    #ql.os.set_api("SIGSEGV", crash_handler)
    ql.os.set_api(".*", "*", exception_hook)
    ql.run()
    coverage_info = {
        "input_file": input_file,
        "coverage": list(coverage)
    }
    print(len(coverage))
    update_coverage(input_file, data)

def clear_tmp():
    dir_path = "rootfs/tmp/"
    file_list = os.listdir(dir_path)
    for file_name in file_list:
        file_path = os.path.join(dir_path, file_name)
        os.remove(file_path)

coverage = set()
all_coverage =set()
#paths:
cmd = "rootfs/exifsan"
rootfs_path = "rootfs/"
corpus_path = "rootfs/corpus/"
corpus = glob.glob(os.path.join(corpus_path, "*"))
counter = 0
while counter<100:
    harness()
    counter += 1
    clear_tmp()
coverage.clear()