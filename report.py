import math
import os
import sys
import json
import errno
import texttable

def load_json(file_name):
    if os.path.exists(file_name):
        f = open(file_name, "r")
        data = json.load(f)
        return data

def table_one(file_name, output):
    table = texttable.Texttable()
    table.set_cols_align(["c", "c", "c", "c", "c", "c", "c", "c", "c", "c", "c", "c"])
    table.set_cols_valign(["m", "m", "m", "m", "m", "m", "m", "m", "m", "m", "m", "m"])
    table.set_cols_width([10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10])
    table.header(
        ["domain_name", "scan_time", "ipv4_addresses", "ipv6_addresses", "insecure_http", "redirect_to_https", "hsts",
         "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"])

    data = load_json(file_name)
    for domain_name in data:
        content = data[domain_name]
        table.add_row([domain_name, content["scan_time"], content["ipv4_addresses"], content["ipv6_addresses"],
                       content["insecure_http"], content["redirect_to_https"], content["hsts"],
                       content["tls_versions"], content["root_ca"], content["rdns_names"],
                       content["rtt_range"], content["geo_locations"]])


    # print(table.draw())
    # with open(output, 'w') as f:
    #     f.write(table.draw())
    return table


def table_two(file_name, output):
    table = texttable.Texttable()
    table.set_cols_align(["c", "c", "c"])
    table.set_cols_valign(["m", "m", "m"])
    table.set_cols_width([10, 10, 10])

    data = load_json(file_name)
    rtt_data = dict()
    for domain_name in data:
        rtt_data[domain_name] = {
            "min": math.inf,
            "max": -1 * math.inf,
        }
        if len(data[domain_name]["rtt_range"]) > 0:
            min = data[domain_name]["rtt_range"][0]
            rtt_data[domain_name]["min"] = min
        if len(data[domain_name]["rtt_range"]) > 1:
            max = data[domain_name]["rtt_range"][1]
            rtt_data[domain_name]["max"] = max

    rtt_data = sorted(rtt_data.items(), key=lambda k: k[1]["min"], reverse=False)
    for each in rtt_data:
        content = each[1]
        table.add_row([each[0], content.get("min"), content.get("max")])

    # print(table.draw())
    # with open(output, 'w') as f:
    #     f.write(table.draw())

    return table



def process_report(file_name, output):
    table1 = table_one(file_name, output)
    table2 = table_two(file_name, output)
    with open(output, 'w') as f:
        f.write(table1.draw())
        f.write(table2.draw())
    f.close()


if __name__ == '__main__':
    n = len(sys.argv)
    if n < 2:
        sys.stderr.write("Please type in input and output file")
        sys.exit(errno.EACCES)
    file_name = sys.argv[1]
    output = sys.argv[2]
    process_report(file_name, output)
