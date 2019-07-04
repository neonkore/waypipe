#!/usr/bin/env python3

import os, sys, fnmatch
import xml.etree.ElementTree as ET

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


def write_enum(is_header, ostream, iface_name, enum):
    if not is_header:
        return

    enum_name = enum.attrib["name"]
    is_bitfield = "bitfield" in enum.attrib and enum.attrib["bitfield"] == "true"

    for entry in enum:
        if entry.tag != "entry":
            continue
        entry_name = entry.attrib["name"]
        entry_value = entry.attrib["value"]

        full_name = (iface_name + "_" + enum_name + "_" + entry_name).upper()
        print("#define {} {}".format(full_name, entry_value), file=ostream)


def is_exportable(func_name, export_list):
    for e in export_list:
        if fnmatch.fnmatchcase(func_name, e):
            return True
    return False


def write_func(is_header, ostream, iface_name, func, is_request, export_list):
    func_name = (
        iface_name + "_" + ("req" if is_request else "evt") + "_" + func.attrib["name"]
    )

    for_export = is_exportable(func_name, export_list)

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
            c_sig.append("int " + arg_name + "_count")
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
    handle_signature = "void call_{}(struct context *ctx, const uint32_t *payload, const int *fds, struct message_tracker *mt)".format(
        func_name
    )

    W = lambda *x: print(*x, file=ostream)
    if for_export:
        W(do_signature)
    if is_header and for_export:
        W(handle_signature + ";")
    elif for_export:
        # Write function definition
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
                W("\tuint32_t arg{}_a = (uint32_t)payload[i];".format(i))
                if n_reg_left > 0:
                    W("\ti += 1 + ((arg{}_a + 0x3) >> 2);".format(i))

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

    if is_header:
        msg_data_args = None
    else:
        gaps = [0]
        nta = []
        newvec_idxs = []
        newvec_types = []
        for arg_name, arg_type, arg_interface in w_args:
            if arg_type == "fd":
                continue
            ## New type string uses offsets relative last stretch end
            if arg_type == "new_id":
                newvec_idxs.append(str(gaps[-1]))
                newvec_types.append(
                    "&intf_" + arg_interface if arg_interface is not None else "NULL"
                )

            # Every non-fd element begins with at least one word
            gaps[-1] += 1
            if arg_type in ("string", "array"):
                gaps.append(0)
                nta.append("true" if arg_type == "string" else "false")
                newvec_idxs.append("-1")
                newvec_types.append("NULL")

        base_g = str(gaps[0])
        nts = [str(x) for x in gaps[1:]]

        if len(nts) > 0:
            W("static const bool sis_" + func_name + "[] = {")
            W("\t" + ", ".join(nta))
            W("};")
            W("static const unsigned int gap_" + func_name + "[] = {")
            W("\t" + ", ".join(nts))
            W("};")

        if num_new_args > 0:
            W("static const unsigned int noi_" + func_name + "[] = {")
            W("\t" + ", ".join(newvec_idxs))
            W("};")
            W("static const struct wp_interface *not_" + func_name + "[] = {")
            W("\t" + ", ".join(newvec_types))
            W("};")

        # Write message metadata, for length check/new object initialization
        msg_data_args = []
        msg_data_args.append('"{}"'.format(func.attrib["name"]))
        msg_data_args.append(str(num_stretch_args))
        msg_data_args.append(str(base_g))
        if len(nts) > 0:
            msg_data_args.append("gap_{}".format(func_name))
            msg_data_args.append("sis_{}".format(func_name))
        else:
            msg_data_args.append("NULL")
            msg_data_args.append("NULL")
        msg_data_args.append(str(num_fd_args))
        if num_new_args > 0:
            msg_data_args.append(str(len(newvec_types)))
            msg_data_args.append("noi_{}".format(func_name))
            msg_data_args.append("not_{}".format(func_name))
        else:
            msg_data_args.append("0")
            msg_data_args.append("NULL")
            msg_data_args.append("NULL")

    return (is_request, func_name, func.attrib["name"], msg_data_args)


def write_interface(is_header, ostream, iface_name, func_data):
    reqs, evts = [], []
    for is_req, name, short_name, msg_data_args in func_data:
        if is_req:
            reqs.append((name, short_name, msg_data_args))
        else:
            evts.append((name, short_name, msg_data_args))

    W = lambda *x: print(*x, file=ostream)

    if is_header:
        # Define 'header' type listing functions
        if len(reqs) > 0:
            W("struct req_map_" + iface_name + " {")
            for name, short_name, mda in reqs:
                W("\twp_callfn_t " + short_name + ";")
            W("};")
        if len(evts) > 0:
            W("struct evt_map_" + iface_name + " {")
            for name, short_name, mda in evts:
                W("\twp_callfn_t " + short_name + ";")
            W("};")
    else:
        rcn, ecn = "NULL", "NULL"
        if len(reqs) > 0:
            W("static const struct msg_data reqs_" + iface_name + "[] = {")
            for name, short_name, mda in reqs:
                W("\t{" + ", ".join(mda) + "},")
            W("};")
            rcn = "reqs_" + iface_name
        if len(evts) > 0:
            W("static const struct msg_data evts_" + iface_name + "[] = {")
            for name, short_name, mda in evts:
                W("\t{" + ", ".join(mda) + "},")
            W("};")
            ecn = "evts_" + iface_name
        W("const struct wp_interface intf_" + iface_name + " = {")
        W('\t"{}",'.format(iface_name))
        W("\t{" + rcn + ", " + ecn + "},")
        W("\t{" + str(len(reqs)) + ", " + str(len(evts)) + "},")
        W("};")


if __name__ == "__main__":
    mode, req_file, source, dest = sys.argv[1:]

    export_list = open(req_file).read().split("\n")

    is_header = {"data": False, "header": True}[mode]

    tree = ET.parse(source)
    root = tree.getroot()
    proto_name = root.attrib["name"]
    header_guard = "PROTOCOL_{}_H".format(proto_name.upper())

    intfset = {
        interface.attrib["name"] for interface in root if interface.tag == "interface"
    }
    for intf in root:
        if intf.tag == "interface":
            for func in intf:
                for arg in func:
                    if "interface" in arg.attrib:
                        intfset.add(arg.attrib["interface"])
    interfaces = sorted(intfset)

    with open(dest, "w") as ostream:
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

        for interface in root:
            if interface.tag != "interface":
                continue
            iface_name = interface.attrib["name"]

            func_data = []
            for item in interface:
                if item.tag == "enum":
                    write_enum(is_header, ostream, iface_name, item)
                elif item.tag == "request" or item.tag == "event":
                    func_data.append(
                        write_func(
                            is_header,
                            ostream,
                            iface_name,
                            item,
                            item.tag == "request",
                            export_list,
                        )
                    )
                elif item.tag == "description":
                    pass
                else:
                    raise Exception(item.tag)

            write_interface(is_header, ostream, iface_name, func_data)

        if is_header:
            W()
            W("#endif /* {} */".format(header_guard))
