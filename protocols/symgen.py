#!/usr/bin/env python3

import os, sys, fnmatch
import xml.etree.ElementTree as ET
import argparse

"""
A static protocol code generator.
"""

wltype_to_ctypes = {
    "uint": "uint32_t ",
    "fixed": "uint32_t ",
    "int": "int32_t ",
    "object": "struct wp_object *",
    "new_id": "struct wp_object *",
    "string": "const char *",
    "fd": "int ",
}


def superstring(a, b):
    na, nb = len(a), len(b)
    if nb > na:
        b, a, nb, na = a, b, na, nb
    # A contains B
    for i in range(na - nb + 1):
        if a[i : nb + i] == b:
            return a

    # suffix of B is prefix of A
    ba_overlap = 0
    for i in range(1, nb):
        if b[-i:] == a[:i]:
            ba_overlap = i

    # suffix of A is prefix of B
    ab_overlap = 0
    for i in range(1, nb):
        if a[-i:] == b[:i]:
            ab_overlap = i

    if ba_overlap > ab_overlap:
        return b + a[ba_overlap:]
    else:
        return a + b[ab_overlap:]


def get_offset(haystack, needle):
    for i in range(len(haystack) - len(needle) + 1):
        if haystack[i : i + len(needle)] == needle:
            return i
    return None


def shortest_superstring(strings):
    """
    Given strings L_1,...L_n over domain U, report an approximation
    of the shortest superstring of the lists, and offsets of the
    L_i into this string. Has O(n^3) runtime; O(n^2 polylog) is possible.
    """
    if not len(strings):
        return None

    pool = []
    for s in strings:
        if s not in pool:
            pool.append(s)

    while len(pool) > 1:
        max_overlap = 0
        best = None
        for i in range(len(pool)):
            for j in range(i):
                d = len(pool[i]) + len(pool[j]) - len(superstring(pool[i], pool[j]))
                if d >= max_overlap:
                    max_overlap = d
                    best = (j, i)

        s = superstring(pool[best[0]], pool[best[1]])
        del pool[best[1]]
        del pool[best[0]]
        pool.append(s)

    sstring = pool[0]
    for s in strings:
        assert get_offset(sstring, s) != None, ("substring property", sstring, s)

    return sstring


def write_enum(is_header, ostream, iface_name, enum):
    if not is_header:
        return

    enum_name = enum.attrib["name"]
    is_bitfield = "bitfield" in enum.attrib and enum.attrib["bitfield"] == "true"

    long_name = iface_name + "_" + enum_name
    print("enum " + long_name + " {", file=ostream)
    for entry in enum:
        if entry.tag != "entry":
            continue
        entry_name = entry.attrib["name"]
        entry_value = entry.attrib["value"]

        full_name = long_name.upper() + "_" + entry_name.upper()
        print("\t" + full_name + " = " + entry_value + ",", file=ostream)
    print("};", file=ostream)


def write_version(is_header, ostream, iface_name, version):
    if not is_header:
        return

    print(
        "#define " + iface_name.upper() + "_INTERFACE_VERSION " + str(version),
        file=ostream,
    )


def is_exportable(func_name, export_list):
    for e in export_list:
        if fnmatch.fnmatchcase(func_name, e):
            return True
    return False


def write_func(is_header, ostream, func_name, func):
    c_sig = ["struct context *ctx"]
    w_args = []

    num_fd_args = 0
    num_reg_args = 0
    num_obj_args = 0
    num_new_args = 0
    num_stretch_args = 0
    for arg in func:
        if arg.tag != "arg":
            continue

        arg_name = arg.attrib["name"]
        arg_type = arg.attrib["type"]
        arg_interface = arg.attrib["interface"] if "interface" in arg.attrib else None
        if arg_type == "new_id" and arg_interface is None:
            # Special case, for wl_registry_bind
            c_sig.append("const char *interface")
            c_sig.append("uint32_t version")
            c_sig.append("struct wp_object *id")
            w_args.append(("interface", "string", None))
            w_args.append(("version", "uint", None))
            w_args.append((arg_name, "new_id", None))
            num_obj_args += 1
            num_new_args += 1
            num_reg_args += 3
            num_stretch_args += 1
            continue

        if arg_type == "array":
            c_sig.append("uint32_t " + arg_name + "_count")
            c_sig.append("const uint8_t *" + arg_name + "_val")
        else:
            c_sig.append(wltype_to_ctypes[arg_type] + arg_name)
        w_args.append((arg_name, arg_type, arg_interface))
        if arg_type == "fd":
            num_fd_args += 1
        else:
            num_reg_args += 1
        if arg_type == "object" or arg_type == "new_id":
            num_obj_args += 1
        if arg_type == "new_id":
            num_new_args += 1
        if arg_type in ("array", "string"):
            num_stretch_args += 1

    do_signature = "void do_{}({});".format(func_name, ", ".join(c_sig))
    handle_signature = "static void call_{}(struct context *ctx, const uint32_t *payload, const int *fds, struct message_tracker *mt)".format(
        func_name
    )

    W = lambda *x: print(*x, file=ostream)
    if is_header:
        W(do_signature)
    if not is_header:
        # Write function definition
        W(do_signature)
        W(handle_signature + " {")
        if num_reg_args > 0:
            W("\tunsigned int i = 0;")
        if num_fd_args > 0:
            W("\tunsigned int k = 0;")

        tmp_names = ["ctx"]
        n_fds_left = num_fd_args
        n_reg_left = num_reg_args
        for i, (arg_name, arg_type, arg_interface) in enumerate(w_args):
            if arg_type == "array":
                n_reg_left -= 1
                W(
                    "\tconst uint8_t *arg{}_b = (const uint8_t *)&payload[i + 1];".format(
                        i
                    )
                )
                W("\tuint32_t arg{}_a = payload[i];".format(i))
                if n_reg_left > 0:
                    W("\ti += 1 + (unsigned int)((arg{}_a + 0x3) >> 2);".format(i))

                tmp_names.append("arg{}_a".format(i))
                tmp_names.append("arg{}_b".format(i))
                continue

            tmp_names.append("arg{}".format(i))

            if arg_type == "fd":
                n_fds_left -= 1
                W("\tint arg{} = fds[{}];".format(i, "k++" if n_fds_left > 0 else "k"))
                continue

            n_reg_left -= 1
            if arg_type == "string":
                W("\tconst char *arg{} = (const char *)&payload[i + 1];".format(i))
                W("\tif (!payload[i]) arg{} = NULL;".format(i))
                if n_reg_left > 0:
                    W("\ti += 1 + ((payload[i] + 0x3) >> 2);")
                continue

            i_incr = "i++" if n_reg_left > 0 else "i"

            if arg_type == "object" or arg_type == "new_id":
                if arg_interface is None:
                    intf_str = "NULL"
                else:
                    intf_str = "&intf_" + arg_interface
                W(
                    "\tstruct wp_object *arg{} = get_object(mt, payload[{}], {});".format(
                        i, i_incr, intf_str
                    )
                )
            elif arg_type == "int":
                W("\tint32_t arg{} = (int32_t)payload[{}];".format(i, i_incr))
            elif arg_type == "uint" or arg_type == "fixed":
                W("\tuint32_t arg{} = payload[{}];".format(i, i_incr))

        W("\tdo_{}({});".format(func_name, ", ".join(tmp_names)))
        if num_obj_args == 0:
            W("\t(void)mt;")
        if num_fd_args == 0:
            W("\t(void)fds;")
        if num_reg_args == 0:
            W("\t(void)payload;")

        W("}")


def load_msg_data(func_name, func, for_export):
    w_args = []
    for arg in func:
        if arg.tag != "arg":
            continue
        arg_name = arg.attrib["name"]
        arg_type = arg.attrib["type"]
        arg_interface = arg.attrib["interface"] if "interface" in arg.attrib else None
        if arg_type == "new_id" and arg_interface is None:
            w_args.append(("interface", "string", None))
            w_args.append(("version", "uint", None))
            w_args.append((arg_name, "new_id", None))
        else:
            w_args.append((arg_name, arg_type, arg_interface))

    new_objs = []
    for arg_name, arg_type, arg_interface in w_args:
        if arg_type == "new_id":
            new_objs.append(
                "&intf_" + arg_interface if arg_interface is not None else "NULL"
            )

    # gap coding: 0=end,1=new_obj,2=array,3=string
    num_fd_args = 0
    gaps = [0]
    gap_ends = []
    for arg_name, arg_type, arg_interface in w_args:
        if arg_type == "fd":
            num_fd_args += 1
            continue

        gaps[-1] += 1
        if arg_type in ("new_id", "string", "array"):
            gap_ends.append({"new_id": 1, "string": 3, "array": 2}[arg_type])
            gaps.append(0)
    gap_ends.append(0)
    gap_codes = [str(g * 4 + e) for g, e in zip(gaps, gap_ends)]

    is_destructor = "type" in func.attrib and func.attrib["type"] == "destructor"
    is_request = item.tag == "request"
    short_name = func.attrib["name"]

    return (
        is_request,
        func_name,
        short_name,
        new_objs,
        gap_codes,
        is_destructor,
        num_fd_args,
        for_export,
    )


def write_interface(
    ostream, iface_name, func_data, gap_code_array, new_obj_array, dest_name
):
    reqs, evts = [], []
    for x in func_data:
        if x[0]:
            reqs.append(x)
        else:
            evts.append(x)

    W = lambda *x: print(*x, file=ostream)

    if len(reqs) > 0 or len(evts) > 0:
        W("static const struct msg_data msgs_" + iface_name + "[] = {")

    msg_names = []
    for x in reqs + evts:
        (
            is_request,
            func_name,
            short_name,
            new_objs,
            gap_codes,
            is_destructor,
            num_fd_args,
            for_export,
        ) = x
        msg_names.append(short_name)

        mda = []
        mda.append(
            "gaps_{} + {}".format(dest_name, get_offset(gap_code_array, gap_codes))
        )
        if len(new_objs) > 0:
            mda.append(
                "objt_{} + {}".format(dest_name, get_offset(new_obj_array, new_objs))
            )
        else:
            mda.append("NULL")

        mda.append(("call_" + func_name) if for_export else "NULL")
        mda.append(str(num_fd_args))
        mda.append("true" if is_destructor else "false")

        W("\t{" + ", ".join(mda) + "},")

    mcn = "NULL"
    if len(reqs) > 0 or len(evts) > 0:
        W("};")
        mcn = "msgs_" + iface_name

    W("const struct wp_interface intf_" + iface_name + " = {")
    W("\t" + mcn + ",")
    W("\t" + str(len(reqs)) + ",")
    W("\t" + str(len(evts)) + ",")
    W('\t"{}",'.format(iface_name))
    W('\t"{}",'.format("\\0".join(msg_names)))
    W("};")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", help="Either 'header' or 'data'.")
    parser.add_argument(
        "export_list", help="List of events/requests which need parsing."
    )
    parser.add_argument("output_file", help="C file to create.")
    parser.add_argument("protocols", nargs="+", help="XML protocol files to use.")
    args = parser.parse_args()

    is_header = {"data": False, "header": True}[args.mode]
    if is_header:
        assert args.output_file[-2:] == ".h"
    else:
        assert args.output_file[-2:] == ".c"
    dest_name = os.path.basename(args.output_file)[:-2].replace("-", "_")

    export_list = open(args.export_list).read().split("\n")

    intfset = set()
    for source in args.protocols:
        tree = ET.parse(source)
        root = tree.getroot()
        for intf in root:
            if intf.tag == "interface":
                intfset.add(intf.attrib["name"])
                for msg in intf:
                    for arg in msg:
                        if "interface" in arg.attrib:
                            intfset.add(arg.attrib["interface"])
    interfaces = sorted(intfset)

    header_guard = "{}_H".format(dest_name.upper())
    with open(args.output_file, "w") as ostream:
        W = lambda *x: print(*x, file=ostream)

        if is_header:
            W("#ifndef {}".format(header_guard))
            W("#define {}".format(header_guard))
            W()
        W('#include "symgen_types.h"')
        if not is_header:
            W("#include <stddef.h>")

        for intf in interfaces:
            W("extern const struct wp_interface intf_{};".format(intf))

        gap_code_list = []
        new_obj_list = []

        interface_data = []

        for source in sorted(args.protocols):
            tree = ET.parse(source)
            root = tree.getroot()
            for interface in root:
                if interface.tag != "interface":
                    continue
                iface_name = interface.attrib["name"]

                write_version(
                    is_header, ostream, iface_name, interface.attrib["version"]
                )

                func_data = []
                for item in interface:
                    if item.tag == "enum":
                        write_enum(is_header, ostream, iface_name, item)
                    elif item.tag == "request" or item.tag == "event":
                        is_req = item.tag == "request"
                        func_name = (
                            iface_name
                            + "_"
                            + ("req" if is_req else "evt")
                            + "_"
                            + item.attrib["name"]
                        )

                        for_export = is_exportable(func_name, export_list)
                        if for_export:
                            write_func(is_header, ostream, func_name, item)
                        if not is_header:
                            func_data.append(load_msg_data(func_name, item, for_export))

                    elif item.tag == "description":
                        pass
                    else:
                        raise Exception(item.tag)

                for x in func_data:
                    gap_code_list.append(x[4])
                    new_obj_list.append(x[3])

                interface_data.append((iface_name, func_data))

        if not is_header:
            gap_code_array = shortest_superstring(gap_code_list)
            new_obj_array = shortest_superstring(new_obj_list)

            if new_obj_array is not None:
                W("static const struct wp_interface *objt_" + dest_name + "[] = {")
                W("\t" + ",\n\t".join(new_obj_array))
                W("};")

            if gap_code_array is not None:
                W("static const uint16_t gaps_" + dest_name + "[] = {")
                W("\t" + ",\n\t".join(gap_code_array))
                W("};")

            for iface_name, func_data in interface_data:
                write_interface(
                    ostream,
                    iface_name,
                    func_data,
                    gap_code_array,
                    new_obj_array,
                    dest_name,
                )

        if is_header:
            W()
            W("#endif /* {} */".format(header_guard))
