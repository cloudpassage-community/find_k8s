import cloudpassage
import os
import json
import csv
from pkg_resources import parse_version


def main():
    # Suspect package names
    suspect_packages = "kubectl,kubeadm,kubelet"

    # Suspect processes URL
    procs_url = "/v2/servers?process_name=kubelet,kubeadm,kubectl,kube-proxy"

    # Minimum versions safe from API auth bug
    kube_min_ver = {"1.10": "1.10.11",
                    "1.11": "1.11.5",
                    "1.12": "1.12.3",
                    "1.13": "1.13.0-rc.1"}

    # Get Halo auth info
    key = os.getenv("HALO_API_KEY")
    secret = os.getenv("HALO_API_SECRET_KEY")

    # Set up CloudPassage API abstractions
    session = cloudpassage.HaloSession(key, secret)
    servers = cloudpassage.Server(session)
    scans = cloudpassage.Scan(session)
    helper = cloudpassage.HttpHelper(session)

    # Get servers with suspect packages installed
    servers_installed_kube = [x for x in
                              servers.list_all(package_name=suspect_packages)]

    # Get servers with suspect processes
    servers_running_kube = [x for x in
                            helper.get_paginated(procs_url, "servers", 99)]

    # Print preliminary metrics
    print("Installation match: %s" % len(servers_installed_kube))
    print("Running process match: %s" % len(servers_running_kube))

    # Get a list of all servers with K8s-related procs or packages
    kube_servers = merge_server_lists(servers_installed_kube,
                                      servers_running_kube)
    # Create a dictionary of packages, processes, and metadata for each server.
    inventory = {x["id"]: {"packages": get_package_listing_from_scan(scans.last_scan_results(x["id"], "svm")),  # NOQA
                           "processes": servers.list_processes(x["id"]),
                           "server_metadata": x}
                for x in kube_servers}

    # Print a report to stdout
    print("{}{}{}{}{}{}{}".format("Halo ID".ljust(40),
                                  "CSP account".ljust(40),
                                  "CSP Instance".ljust(40),
                                  "kubectl version".ljust(20),
                                  "kubeadm version".ljust(20),
                                  "kubelet version".ljust(20),
                                  "kubectl vulnerable".ljust(25),
                                  "kubeadm vulnerable".ljust(25),
                                  "kubelet vulnerable".ljust(25),
                                  "k8s processes(below)"))
    for x in inventory.items():
        server_id = x[0]
        server_csp_id = x[1]["server_metadata"]["csp_account_id"] if "csp_account_id" in x[1]["server_metadata"] else ""  # NOQA
        server_instance_id = x[1]["server_metadata"]["csp_instance_id"] if "csp_instance_id" in x[1]["server_metadata"] else ""  # NOQA
        kubectl_version = get_package_version(x[1]["packages"], "kubectl")
        kubeadm_version = get_package_version(x[1]["packages"], "kubeadm")
        kubelet_version = get_package_version(x[1]["packages"], "kubelet")
        kube_procs = get_kube_procs(x[1]["processes"])
        kubectl_vulnerable = is_kube_vulnerable(kube_min_ver, kubectl_version)
        kubeadm_vulnerable = is_kube_vulnerable(kube_min_ver, kubeadm_version)
        kubelet_vulnerable = is_kube_vulnerable(kube_min_ver, kubelet_version)
        print("{}{}{}{}{}{}{}{}{}\n{}\n\n".format(server_id.ljust(40),
                                                  server_csp_id.ljust(40),
                                                  server_instance_id.ljust(40),
                                                  kubectl_version.ljust(16),
                                                  kubeadm_version.ljust(16),
                                                  kubelet_version.ljust(16),
                                                  kubectl_vulnerable.ljust(20),
                                                  kubeadm_vulnerable.ljust(20),
                                                  kubelet_vulnerable.ljust(20),
                                                  kube_procs))
    dump_to_csv(inventory, kube_min_ver)
    dump_to_json(inventory)


def dump_to_csv(inventory, comparisons):
    with open("out.csv", "w") as out_file:
        fieldnames = ["csp_account_id", "csp_instance_id", "halo_id",
                      "kubectl_version", "kubeadm_version", "kubelet_version",
                      "processes", "kubectl_vulnerable", "kubeadm_vulnerable",
                      "kubelet_vulnerable"]
        writer = csv.DictWriter(out_file, fieldnames=fieldnames)
        writer.writeheader()
        for workload_id, meta in inventory.items():
            kubectl_version = get_package_version(meta["packages"], "kubectl")
            kubeadm_version = get_package_version(meta["packages"], "kubeadm")
            kubelet_version = get_package_version(meta["packages"], "kubelet")
            dataz = {"halo_id": workload_id,
                     "csp_account_id": meta["server_metadata"]["csp_account_id"] if "csp_account_id" in meta["server_metadata"] else "",  # NOQA
                     "csp_instance_id": meta["server_metadata"]["csp_instance_id"] if "csp_instance_id" in meta["server_metadata"] else "",  # NOQA
                     "kubectl_version": kubectl_version,
                     "kubeadm_version": kubeadm_version,
                     "kubelet_version": kubelet_version,
                     "processes": "\n".join([x["command"] for x in meta["processes"] if "kube" in x["process_name"]]),  # NOQA
                     "kubectl_vulnerable": is_kube_vulnerable(comparisons,
                                                              kubectl_version),
                     "kubeadm_vulnerable": is_kube_vulnerable(comparisons,
                                                              kubeadm_version),
                     "kubelet_vulnerable": is_kube_vulnerable(comparisons,
                                                              kubelet_version)}
            writer.writerow(dataz)
    print("Wrote out.csv")
    return


def dump_to_json(inventory):
    with open("out.json", "w") as out_file:
        json.dump(inventory, out_file)
    print("Wrote out.json")


def merge_server_lists(list_1, list_2):
    observed = set({})
    list_1.extend(list_2)
    cleaned = []
    for server in list_1:
        if server["id"] in observed:
            continue
        else:
            cleaned.append(server)
            observed.add(server["id"])
    return cleaned


def get_kube_procs(procs):
    kube_procs = ["      {}".format(x["command"]) for x in procs
                  if "kube" in x["process_name"]]
    return "\n".join(kube_procs)


def get_package_version(packages, package_name):
    for p_name, p_version in packages.items():
        if p_name.startswith(package_name):
            return(p_version)
    return "NONE"


def is_kube_vulnerable(comparisons, actual):
    try:
        if actual == "NONE":
            return "INDETERMINATE"
        majorminor = str(".".join(actual.split(".")[:2]))

        # We know all these are vulnerable
        if majorminor in ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5",
                          "1.6", "1.7", "1.8", "1.9"]:
            return "YES"
        comparator = comparisons[majorminor]
        if parse_version(actual) < parse_version(comparator):
            retval = "YES"
        else:
            retval = "NO"
    except KeyError as e:
        print("Comp: {}  Act: {}".format(comparisons, actual))
        raise e
    return retval


def get_package_listing_from_scan(scan):
    return {x["package_name"]: x["package_version"]
            for x in scan["scan"]["findings"]}


if __name__ == "__main__":
    main()
