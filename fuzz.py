from qiling.const import QL_VERBOSE
from qiling import *
import sys
import random
from pexpect import run
from pipes import quote
from qiling.extensions.coverage import utils as cov_utils
import secrets
import os

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
    mutated_file = os.path.join(corpus_path, os.path.basename(input_file))
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
        mutated_file = os.path.join(corpus_path, os.path.basename(input_file))
        with open(mutated_file, "wb") as f:
            f.write(mutated_input)
        all_coverage.update(coverage)

def harness(input_file):
    data = get_bytes(input_file)
    mutator(data)
    mutate_file(input_file, data)
    ql = Qiling([cmd, input_file, "-verbose"], rootfs_path, verbose=QL_VERBOSE.OFF)
    ql.hook_block(callback)
    ql.add_fs_mapper(cmd, "exifsan")
    ql.add_fs_mapper(snapshot_path, "snapshot.bin")
    ql.add_fs_mapper( corpus_path, "corpus/")
    ql.add_fs_mapper('/proc', '/proc')
    ql.restore(snapshot=snapshot_path)
    begin_point = X64BASE + 0xbe5
    ql.run(begin = begin_point)
    coverage_info = {
        "input_file": input_file,
        "coverage": list(coverage)
    }
    print(len(coverage))
    update_coverage(input_file, data)

coverage = set()
all_coverage =set()
#paths:
cmd = "rootfs/exifsan"
rootfs_path = "rootfs/"
snapshot_path = "snapshot.bin"
corpus_path = rootfs_path + "corpus/"


if len(sys.argv) < 2:
    print("Usage: fuzz.py <valid_jpg>")
else:
    filename = sys.argv[1]
    counter = 0
    ql = Qiling([cmd, filename, "-verbose"], rootfs_path, verbose=QL_VERBOSE.OFF)
    ql.add_fs_mapper(cmd, "exif")
    ql.add_fs_mapper(snapshot_path, "snapshot.bin")
    ql.add_fs_mapper( corpus_path, "corpus/")
    ql.add_fs_mapper('/proc', '/proc')
    X64BASE = int(ql.profile.get("OS64", "load_address"), 16)
    ql.hook_address(dump, X64BASE + 0xbe5)
    ql.run()
    while counter<100:
        harness(rootfs_path+filename)
        counter += 1
    coverage.clear()