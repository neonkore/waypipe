#!/usr/bin/env python3

import os, sys, fnmatch
import xml.etree.ElementTree as ET

"""
A static protocol code generator for the task of creating the wire representation
of a list of events/requests
"""

wltype_to_ctypes = {
    "uint": "uint32_t ",
    "fixed": "uint32_t ",
    "int": "int32_t ",
    "object": "struct wp_objid ",
    "new_id": "struct wp_objid ",
    "string": "const char *",
    "fd": "int ",
}


def write_enum(ostream, iface_name, enum):
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


def write_func(ostream, iface_name, func, is_request, func_no, export_list):
    func_name = (
        iface_name + "_" + ("req" if is_request else "evt") + "_" + func.attrib["name"]
    )

    for_export = is_exportable(func_name, export_list)
    if not for_export:
        return

    c_sig = ["struct transfer_states *ts", "struct wp_objid " + iface_name + "_id"]
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
            c_sig.append("struct wp_objid id")
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

    send_signature = "static void send_{}({}) ".format(func_name, ", ".join(c_sig))

    W = lambda *x: print(*x, file=ostream)

    # Write function definition
    W(send_signature + " {")
    W("\tts->fd_size = 0;")
    W("\tts->msg_space[0] = {}.id;".format(iface_name + "_id"))
    W("\tts->msg_size = 2;")

    tmp_names = ["ctx"]
    for i, (arg_name, arg_type, arg_interface) in enumerate(w_args):
        if arg_type == "array":
            raise NotImplementedError()
            continue
        elif arg_type == "fd":
            W("\tts->fd_space[ts->fd_size++] = {};".format(arg_name))
            continue
        elif arg_type == "string":
            W("\tserialize_string(ts, {});".format(arg_name))
            continue
        elif arg_type == "object" or arg_type == "new_id":
            W("\tts->msg_space[ts->msg_size++] = {}.id;".format(arg_name))
        elif arg_type == "int":
            W("\tts->msg_space[ts->msg_size++] = (uint32_t){};".format(arg_name))
        elif arg_type == "uint" or arg_type == "fixed":
            W("\tts->msg_space[ts->msg_size++] = {};".format(arg_name))
        else:
            raise KeyError(arg_type)

    W("\tts->msg_space[1] = ((uint32_t)ts->msg_size << 18) | {};".format(func_no))
    if is_request:
        W("\tts->send(ts, ts->app, ts->comp);")
    else:
        W("\tts->send(ts, ts->comp, ts->app);")

    W("}")


if __name__ == "__main__":
    req_file, dest = sys.argv[1:3]
    sources = sys.argv[3:]
    assert dest.endswith(".h")
    dest_shortname = dest[:-2]
    header_flag = dest_shortname.upper().replace("/", "_") + "_H"

    export_list = open(req_file).read().split("\n")

    with open(dest, "w") as ostream:
        W = lambda *x: print(*x, file=ostream)

        W("#ifndef {}".format(header_flag))
        W("#include <stddef.h>")
        W("#include <stdint.h>")
        W("#include <string.h>")
        W("struct test_state;")
        W("struct wp_objid { uint32_t id; };")
        W("struct transfer_states {")
        W("\tuint32_t msg_space[256];")
        W("\tint fd_space[16];")
        W("\tunsigned int msg_size;")
        W("\tunsigned int fd_size;")
        W("\tstruct test_state *app;")
        W("\tstruct test_state *comp;")
        W(
            "\tvoid (*send)(struct transfer_states *, struct test_state *src, struct test_state *dst);"
        )
        W("};")
        # note: this script assumes that serialize_string will be used
        W("static void serialize_string(struct transfer_states *ts, const char *str) {")
        W("\tif (str) {")
        W("\t\tsize_t slen = strlen(str) + 1;")
        W("\t\tts->msg_space[ts->msg_size] = (uint32_t)slen;")
        W("\t\tmemcpy(&ts->msg_space[ts->msg_size + 1], str, slen);")
        W("\t\tts->msg_size += ((uint32_t)slen + 0x7) >> 2;")
        W("\t} else {")
        W("\t\tts->msg_space[ts->msg_size++] = 0;")
        W("\t}")
        W("}")

        for source in sorted(sources):
            tree = ET.parse(source)
            root = tree.getroot()
            for interface in root:
                if interface.tag != "interface":
                    continue
                iface_name = interface.attrib["name"]

                func_data = []
                nreq, nevt = 0, 0
                for item in interface:
                    if item.tag == "enum":
                        write_enum(ostream, iface_name, item)
                    elif item.tag == "request":
                        write_func(ostream, iface_name, item, True, nreq, export_list)
                        nreq += 1
                    elif item.tag == "event":
                        write_func(ostream, iface_name, item, False, nevt, export_list)
                        nevt += 1
                    elif item.tag == "description":
                        pass
                    else:
                        raise Exception(item.tag)

        W("#endif /* {} */".format(header_flag))
