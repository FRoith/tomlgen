from collections import Counter
import toml
import logging
import random
import argparse
import subprocess
from constants_ext import *
from riscv_opcodes import parse

IS_32_BIT = False
IS_COMPRESSED = False

class Hex():
    def __init__(self, value: int):
        self.value = value

    def __repr__(self):
        return hex(self.value)

class TomlHexEncoder(toml.TomlEncoder):
    def __init__(self, _dict=dict, preserve=False):
        super(TomlHexEncoder, self).__init__(_dict, preserve)
        self.dump_funcs[Hex] = self._dump_hex

    def _dump_hex(self, v):
        return f"{v}"

def create_pattern(data_args):
    patt = data_args
    
    if Mapping_vm[0] in patt:
        patt = patt.replace(Mapping_vm[0], "%M_VM%")
    if Mapping_vtypei[hex(0)] in patt:
        patt = patt.replace(Mapping_vtypei[hex(0)], "%M_VTI%")
    if Register_vec[1] in patt:
        patt = patt.replace(Register_vec[1], "%R_V%")
    if Register_int_c[0] in patt:
        patt = patt.replace(Register_int_c[0], "%R_IC%")
    if Register_float_c[0] in patt:
        patt = patt.replace(Register_float_c[0], "%R_FC%")
    if Register_int[0] in patt:
        patt = patt.replace(Register_int[0], "%R_I%")
    if Register_float[0] in patt:
        patt = patt.replace(Register_float[0], "%R_F%")
    if Mapping_fence[0] in patt:
        patt = patt.replace(Mapping_fence[0], "%M_FENCE%")
    if Mapping_round[0] in patt:
        patt = patt.replace(Mapping_round[0], "%M_ROUND%")
    if Mapping_ordering[1] in patt:
        patt = patt.replace(Mapping_ordering[1], "%M_ORDER%")
    if Mapping_csr[hex(1)] in patt:
        patt = patt.replace(Mapping_csr[hex(1)], "%M_CSR%")
    if Mapping_seg[1] in patt:
        patt = patt.replace(Mapping_seg[1], "%M_SEG%")
    if "0x0" in patt:
        patt = patt.replace(" 0x0", " %Ih%")
    if " 0" in patt:
        patt = patt.replace(" 0", " %Id%")

    patt_out = patt
    patt = "^" + re.escape(patt) + "$"
    patt = patt.replace("%M_VM%", f"({re.escape(Mapping_vm[0])}|{re.escape(Mapping_vm[1])})")
    patt = patt.replace("%M_VTI%", f"({re.escape(Mapping_vtypei[hex(0)])}|{re.escape(Mapping_vtypei[hex(1)])})")
    patt = patt.replace("%R_V%", f"({re.escape(Register_vec[0])}|{re.escape(Register_vec[1])})")
    patt = patt.replace("%R_I%", f"({re.escape(Register_int[0])}|{re.escape(Register_int[1])})")
    patt = patt.replace("%R_F%", f"({re.escape(Register_float[0])}|{re.escape(Register_float[1])})")
    patt = patt.replace("%R_IC%", f"({re.escape(Register_int_c[0])}|{re.escape(Register_int_c[1])})")
    patt = patt.replace("%R_FC%", f"({re.escape(Register_float_c[0])}|{re.escape(Register_float_c[1])})")
    patt = patt.replace("%M_FENCE%", f"({re.escape(Mapping_fence[0])}|{re.escape(Mapping_fence[1])})")
    patt = patt.replace("%M_ROUND%", f"({re.escape(Mapping_round[0])}|{re.escape(Mapping_round[1])})")
    patt = patt.replace("%M_ORDER%", f"({re.escape(Mapping_ordering[1])}|{re.escape(Mapping_ordering[2])}|{re.escape(Mapping_ordering[3])})")
    patt = patt.replace("%M_CSR%", f"({re.escape(Mapping_csr[hex(1)])}|{re.escape(Mapping_csr[hex(2)])})")
    patt = patt.replace("%M_SEG%", f"({re.escape(Mapping_seg[1])}|{re.escape(Mapping_seg[0])})")
    patt = patt.replace("%Ih%", f"(-?0x[0-9a-fA-F]+)")
    patt = patt.replace("%Id%", f"(-?[0-9]+)")
    i = 0
    type_map = {"%M_SEG%": ["Mapping_seg"], "%M_CSR%": ["Mapping_csr"], "%M_ORDER%": ["Mapping_ordering"], "%M_VM%": ["Mapping_vm"], "%M_VTI%": ["Mapping_vtypei", "hex"], "%R_V%": ["Register_vec"], "%R_I%": ["Register_int"], "%R_F%": ["Register_float"], "%R_IC%": ["Register_int_c"], "%R_FC%": ["Register_float_c"], "%M_FENCE%": ["Mapping_fence"], "%M_ROUND%": ["Mapping_round"], "%Ih%": ["VInt", "hex"], "%Id%": ["VInt"]}
    types = [type_map[m] for m in re.findall("(%R_[A-Z]*%|%M_[A-Z]*%|%Ih%|%Id%)", patt_out)]
    while "%" in patt_out:
        patt_out = re.sub(r"%R_[A-Z]*%|%M_[A-Z]*%|%Ih%|%Id%", f"${i}$", patt_out, 1)
        i += 1
    return patt, patt_out, types

def aquire_parts(val_to_aquire, extensions, name):
    extensions_loc = [ex.capitalize() for ex in extensions if ex != "I"]
    f = open("/tmp/rvobj", "wb")
    f.write(val_to_aquire.to_bytes(2 if IS_COMPRESSED else 4, byteorder="little"))
    f.close()
    subprocess.call(f"llvm-objcopy -I binary -O elf{32 if IS_32_BIT else 64}-littleriscv --rename-section=.data=.text,code /tmp/rvobj /tmp/rvelf", shell=True)
    subprocess.call(f"llvm-objdump{' --mattr=+' + ',+'.join(extensions_loc) if len(extensions_loc) > 0 else ''} -d -Mno-aliases /tmp/rvelf | tail -n 1 > /tmp/rvdump", shell=True)
    f = open("/tmp/rvdump", "r")
    data = f.read()
    f.close()
    data = data.strip().split("\t")
    return (" ".join(data[1:])).replace(name, "$name$")

def get_from_objdump(name, mask, match, var_fields, extensions=[]):
    for extension in extensions:
        if extension in SUPPORTED_EXTENSIONS:
            break
    else:
        return "TODO: Please implement format manually", []

    test_val = match
    for variable in var_fields:
        if variable in special_tests:
            top, bot = arg_lut[variable]
            test_val |= (special_tests[variable][0] << bot)

    data_args = aquire_parts(test_val, extensions, name.replace("_", "."))
    re_patt, outformat, outtypes = create_pattern(data_args)
    outtype_map = {}
    baseline = re.match(re_patt, data_args)
    if baseline is None:
        return "<unknown>", []
    else:
        baseline = baseline.groups()
    if "<unknown>" in data_args:
        return "<unknown>", []
    if len(data_args) > 0:
        var_fmts = []
        reg_maps = {}
        i = 0
        consts = []
        for variable in var_fields:
            _, bot = arg_lut[variable]
            val = test_val
            if variable in special_tests:
                top, bot = arg_lut[variable]
                val ^= (special_tests[variable][0] << bot)
                val |= (special_tests[variable][1] << bot)
            else:
                val |= (1 << bot)
            new_args = aquire_parts(val, extensions, name.replace("_", "."))
            if " " not in new_args:
                consts.append(variable)
                continue
            other = re.match(re_patt, new_args)
            if other is None:
                consts.append(variable)
                continue
            else:
                other = other.groups()
            i = 0
            for x,y in zip(baseline, other):
                if x != y:
                    outformat = outformat.replace(f"${i}$", f"%{variable}%")
                    outtype_map[variable] = outtypes[i][0]
                i += 1
        unused = re.findall(r"\$[0-9]\$", outformat)
        if len(consts) == 1 == len(unused):
            outformat = outformat.replace(unused[0], f"%{consts[0]}%")
        return outformat, outtype_map
    else:
        return "$name$", []

def make_toml(instr_dict, sets, outfilename, version_infos):
    global IS_COMPRESSED
    pfx = 0
    width = 0
    sfx = []
    for iset in sets:
        prefix, *suffix = tuple(iset.split("_"))
        if "32" in prefix:
            if pfx != 32 and pfx != 0:
                pfx = -1
            pfx = 32
        if "64" in prefix:
            if pfx != 64 and pfx != 0:
                pfx = -1
            pfx = 64
        if "128" in prefix:
            raise Exception("128 bit instruction sets not yet supported")
        for s in suffix:
            if s.capitalize() not in sfx:
                sfx.append(s.capitalize())
            if s.capitalize() in COMPRESSED_SETS:
                if width != 16 and width != 0:
                    raise Exception("Combining 16 and 32 bit instructions in one TOML file is not supported!")
                width = 16
                IS_COMPRESSED = True
            else:
                if width != 32 and width != 0:
                    raise Exception("Combining 16 and 32 bit instructions in one TOML file is not supported!")
                width = 32

    full_toml = {}
    full_toml["set"] = f"RV{pfx if pfx > 0 else ''}{''.join(sfx)}"
    full_toml["width"] = width

    type_dict = {}
    my_lut = {}
    i = 0
    for instr in instr_dict:
        if "aq" in instr_dict[instr]["variable_fields"] and "rl" in instr_dict[instr]["variable_fields"]:
            instr_dict[instr]["variable_fields"].remove("aq")
            instr_dict[instr]["variable_fields"].remove("rl")
            instr_dict[instr]["variable_fields"].append("aqrl")
        type_key = "-".join(instr_dict[instr]["variable_fields"])
        for part in instr_dict[instr]["variable_fields"]:
            if part not in my_lut:
                my_lut[part] = arg_lut[part]
        if type_key not in type_dict:
            i+=1
            type_dict[type_key] = f"type-{i}"

    my_part_types = {}
    new_type_dict = {}
    for typ in type_dict:
        pts = typ.split("-")
        if "" in pts:
            my_part_types["@0"] = [("none", width-1, 0)]
            new_type_dict["@0"] = f"{type_dict[typ]}-0"
            continue # in case of no types
        pts.sort(key=lambda x: arg_lut[x][0], reverse=True)
        pts_types = [data_types[pt] for pt in pts]
        choice_complexity = 1
        for pts_type in pts_types:
            if (len(pts_type) != 0):
                choice_complexity *= len(pts_type)

        for choice in range(choice_complexity):
            i = width - 1
            orig_choice = choice
            part_type = []
            for pts_type,pt in zip(pts_types,pts):
                ppt = pt
                if len(pts_type) > 1:
                    ppt = f"{pt}_{pts_type[choice % len(pts_type)]}"
                    choice //= len(pts_type)
                if my_lut[pt][0] < i:
                    part_type.append(("none", i, my_lut[pt][0]+1))
                part_type.append((ppt, my_lut[pt][0]-my_lut[pt][1], 0))
                i = my_lut[pt][1]-1
            if i > 0:
                part_type.append(("none", i, 0))
            my_part_types[f"{typ}@{orig_choice}"] = part_type
            new_type_dict[f"{typ}@{orig_choice}"] = f"{type_dict[typ]}-{orig_choice}"
    type_dict = new_type_dict

    full_toml["types"] = {}
    full_toml["types"]["names"] = []        

    full_toml["types"]["parts"] = []

    for lut in my_lut:
        rts = data_types[lut]
        my_lut[lut] += (rts,)
        if lut in imm_mappings:
            continue # skip adding part type if imm
        if len(rts) == 0:
            full_toml["types"]["parts"].append([lut, my_lut[lut][0]-my_lut[lut][1]+1, "VInt"])
        elif len(rts) == 1:
            for mapping in Mappings:
                    if rts[0] == mapping["name"]:
                        mapping["use"] = True
            full_toml["types"]["parts"].append([lut, my_lut[lut][0]-my_lut[lut][1]+1, rts[0]])
        else:
            for rt in rts:
                for mapping in Mappings:
                    if rt == mapping["name"]:
                        mapping["use"] = True
                full_toml["types"]["parts"].append([f"{lut}_{rt}", my_lut[lut][0]-my_lut[lut][1]+1, rt])
    full_toml["types"]["parts"].append(["none", 32, "u32"])
    full_toml["types"]["parts"].append(["imm", 32, "VInt"])
    full_toml["types"]["parts"].append(["himm", 32, "VInt", "hex"])

    full_toml["type"] = {}
    full_toml["type"]["names"] = []
    found = set()
    for part_type in my_part_types:
        all_matches = [(instr, part_type) for instr in instr_dict if part_type.startswith(f'{"-".join(instr_dict[instr]["variable_fields"])}@')]
        format_name = type_dict[part_type].replace("type", "format")

        if len(all_matches) == 0:
            continue

        cool_matches = {}
        cool_match_types = {}
        outtypes = {}
        for first_match, ptype in all_matches:
            if first_match in found:
                continue
            mask = int(instr_dict[first_match]['mask'], base=0)
            match = int(instr_dict[first_match]['match'], base=0)
            var_fields = instr_dict[first_match]['variable_fields']
            extensions = [ex.split("_")[1].capitalize() for ex in instr_dict[first_match]['extension']]

            cool_matches[first_match], outtypes[first_match] = get_from_objdump(first_match, mask, match, var_fields, extensions)
            cool_idx = 0
            for vfield in instr_dict[first_match]["variable_fields"]:
                vtypes = data_types[vfield]

                if vfield in imm_mappings:
                    cool_matches[first_match] = cool_matches[first_match].replace(f"%{vfield}%", f"%imm%")

                if len(vtypes) < 2 or vfield not in outtypes[first_match]:
                    continue
                cool_idx *= len(vtypes)
                cool_idx += vtypes.index(outtypes[first_match][vfield])
                cool_matches[first_match] = cool_matches[first_match].replace(f"%{vfield}%", f"%{vfield}_{outtypes[first_match][vfield]}%")
            if ptype == "-".join(instr_dict[first_match]["variable_fields"]) + "@" + f"{cool_idx}":
                cool_match_types[first_match] = f"@{cool_idx}"
                print(f"\"{cool_matches[first_match]}\" found for \"{first_match}\"")
                found.add(first_match)
            else:
                del cool_matches[first_match]

        if len(cool_matches) == 0:
            continue

        full_toml["types"]["names"].append(type_dict[part_type].replace('type', 'format'))
        full_toml[format_name] = {"type": type_dict[part_type]}
        full_toml[format_name]["repr"] = {}
        full_toml[format_name]["instructions"] = {}
        for instr in instr_dict:
            if instr not in cool_match_types:
                continue
            type_key = "-".join(instr_dict[instr]["variable_fields"]) + cool_match_types[instr]
            if part_type == type_key:
                full_toml[format_name]["instructions"][instr] = { "mask": Hex(int(instr_dict[instr]['mask'], base=0)), "match": Hex(int(instr_dict[instr]['match'], base=0))}
                if any([vf in unsigned_list for vf in instr_dict[instr]['variable_fields']]):
                    full_toml[format_name]["instructions"][instr]["unsigned"] = True

        if len(full_toml[format_name]["instructions"]) == 0:
            continue

        full_toml["type"]["names"].append(type_dict[part_type])
        full_toml["type"][type_dict[part_type]] = []
        for sub_type in my_part_types[part_type]:
            if sub_type[0] in imm_mappings:
                for mapping in imm_mappings[sub_type[0]]:
                    p = {}
                    p["name"] = "imm"
                    p["top"] = mapping[0]
                    p["bot"] = mapping[1]
                    full_toml["type"][type_dict[part_type]].append(p)
            else:
                p = {}
                p["name"] = sub_type[0]
                p["top"] = sub_type[1]
                p["bot"] = sub_type[2]
                full_toml["type"][type_dict[part_type]].append(p)      

        cool_counter = Counter(cool_matches.values())
        if len(cool_counter) == 2 and "<unknown>" in cool_counter: # if only one choice for unknown repr, just assume
            most_common, _ = list(filter(lambda x : x[0] != "<unknown>", cool_counter.most_common(2)))[0]
            full_toml[format_name]["repr"]["default"] = most_common
        else:
            most_common, _ = cool_counter.most_common(1)[0]
            full_toml[format_name]["repr"]["default"] = most_common
            for key in cool_matches:
                if cool_matches[key] != most_common:
                    full_toml[format_name]["repr"][key] = cool_matches[key]

    full_toml["mappings"] = {}
    full_toml["mappings"]["names"] = []
    full_toml["mappings"]["number"] = 32

    for mapping in Mappings:
        if mapping["use"]:
            full_toml["mappings"]["names"].append(mapping["name"])
            full_toml["mappings"][mapping["name"]] = mapping["pointer"]

    of = open(outfilename, "w")
    for vinf in version_infos:
        print(f"#{vinf}", file=of)
    toml.dump(full_toml, of, TomlHexEncoder())
    of.close()

def make_tests(instr_dict, sets):
    f = open("/tmp/rvobj", "wb")
    splitsets = [s.split('_')[1].capitalize() for s in sets]
    extensions_loc = [ex for ex in splitsets if ex != "I"]
    print(instr_dict)

    for instr in instr_dict:
        mask = int(instr_dict[instr]['mask'], base=0)
        match = int(instr_dict[instr]['match'], base=0)
        var_fields = instr_dict[instr]['variable_fields']


        for i in range(30):
            field = match | ((~mask) & int.from_bytes(random.randbytes(4), byteorder="little"))
            f.write(field.to_bytes(4, byteorder="little"))
    f.close()
    subprocess.call(f"llvm-objcopy -I binary -O elf{32 if IS_32_BIT else 64}-littleriscv --rename-section=.data=.text,code /tmp/rvobj /tmp/rvelf", shell=True)
    subprocess.call(f"llvm-objdump{' --mattr=+' + ',+'.join(extensions_loc) if len(extensions_loc) > 0 else ''} -d -Mno-aliases /tmp/rvelf | tail -n +10 | grep -v -E '<unknown>' | awk -f reformat.awk > tests.test", shell=True)

def main():
    global IS_32_BIT
    parser = argparse.ArgumentParser(description="Generate RISC-V toml files for use in https://github.com/ics-jku/instruction-decoder\n\n  MANUAL POST-PROCESSING REQUIRED!")
    parser.add_argument("-test", action="store_true", help="Generate tests")
    parser.add_argument("-b32", action="store_true", help="Tell LLVM to use 32 bit instruction decoding instead of 64 bit (used for correct generation of RV32 instruction sets)")
    parser.add_argument("-o", "--outfilename", type=str, help="Filename of output file to put toml data into.", default="instr-table.toml")
    parser.add_argument(
        "extensions",
        nargs="*",
        help="Extensions to use. This is a glob of the rv_.. files, e.g. 'rv*' will give all extensions.",
    )

    args = parser.parse_args()

    IS_32_BIT = args.b32

    # check for LLVM and version
    error = False
    status, result = subprocess.getstatusoutput('llvm-objcopy --version')
    if status != 0:
        logging.error('llvm-objcopy not found, use most recent version for best results')
        error = True

    status, result = subprocess.getstatusoutput('llvm-objdump --version')
    version_infos = []
    if status != 0:
        logging.error('llvm-objdump not found, use most recent version for best results')
        error = True
    else:
        version_infos.append(result.split("\n")[0].strip())
        logging.info(f'using {version_infos[-1]}')

    status, result = subprocess.getstatusoutput('git submodule')
    if status != 0:
        logging.error('git submodule call to determine riscv-opcodes version failed')
        error = True
    else:
        version_infos.append("riscv-opcodes commit hash " + result.strip().split(" ")[0])
        logging.info(f'using {version_infos[-1]}')


    if error:
        exit(-1)
    instr_dict_toml = parse.create_inst_dict(args.extensions, False, include_pseudo_ops=emitted_pseudo_ops)
    instr_dict_toml = dict(sorted(instr_dict_toml.items()))

    make_toml(instr_dict_toml, args.extensions, args.outfilename, version_infos)
    logging.info('instr-table.toml generated successfully')

    if args.test:
        pass

if __name__ == "__main__":
    main()