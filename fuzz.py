from qiling.const import QL_VERBOSE
from qiling import *
import sys
import random
from pexpect import run
from pipes import quote
from qiling.extensions.coverage import utils as cov_utils

def get_bytes(filename):
	f = open('rootfs/'+filename, "rb").read()
	return bytearray(f)

def magic(data):
    magic_vals = [(1, 255), (1, 255), (1, 127), (1, 0), (2, 255), (2, 0), (4, 255), (4, 0), (4, 128), (4, 64), (4, 127)]
    choice = random.choice(magic_vals)
    length = len(data) - 8
    index = range(0, length)
    picked_index = random.choice(index)
    for i in range(choice[0]):
        if choice[0] == 4:
            if choice[1] in [128, 64]:
                if i > 0:
                    data[picked_index+i] = 0
                else:
                    data[picked_index+i] = choice[1]
            elif choice[1] == 127:
                if i > 0:
                    data[picked_index+i] = 255
                else:
                    data[picked_index+i] = choice[1]
            else:
                data[picked_index+i] = choice[1]
        else:
            data[picked_index+i] = choice[1]
    return data

def mutate_file(data):
    f = open("rootfs/mutated.jpg", "wb+")
    f.write(data)
    f.close()

def flip_bit(byte_array, index):
    """Flips the bit at the given index in the byte array"""
    byte_index = index // 8
    bit_index = index % 8
    byte_array[byte_index] ^= 1 << bit_index
    return byte_array

def mutator(data):
    option = [0,1]
    picked_mutation = random.choice(option)
    if picked_mutation == 0:
        #1
        num_of_flips = int((len(data) - 4) * .01)
        indexes = range(4, (len(data) - 4))
        chosen_indexes = []
        counter = 0
        while counter < num_of_flips:
            chosen_indexes.append(random.choice(indexes))
            counter += 1
        for i in chosen_indexes:
            data = flip_bit(data,i)
    elif picked_mutation == 1:
        #2
        data = magic(data)
    mutate_file(data)
    

def by_pass_isa_check(ql: Qiling) -> None:
    print("by_pass_isa_check():")
    ql.arch.regs.rip += 0x15
    pass

def dump(ql, *args, **kw):
    ql.save(reg=False, cpu_context=True, snapshot="snapshot.bin")
    ql.emu_stop()

def harness(filename):
    data = get_bytes(filename)
    mutator(data)
    cmd = "./exif"
    ql = Qiling([cmd,filename,"-verbose"], "./rootfs/", verbose=QL_VERBOSE.DEFAULT)
    ql.add_fs_mapper('/proc', '/proc')
    ql.restore(snapshot="snapshot.bin")
    begin_point = X64BASE + 0xbe5
    with cov_utils.collect_coverage(ql, 'drcov', 'rootfs/output.cov'):
        ql.run(begin = begin_point)

if len(sys.argv) < 2:
    print("Usage: fuzz.py <valid_jpg>")
else:
    cmd = "./exif"
    filename = sys.argv[1]
    counter = 0
    while counter<100:
        ql = Qiling([cmd,filename,"-verbose"], "./rootfs/", verbose=QL_VERBOSE.DEFAULT)
        ql.add_fs_mapper('/proc', '/proc')
        X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
        ql.hook_address(dump, X64BASE + 0xbe5)
        ql.run()
        harness(filename)
        counter += 1