def add_colons_to_mac(mac_addr):
    s = list()
    for i in range(12/2):
        s.append(mac_addr[i*2:i*2+2])
    mac_with_colons = ":".join(s)
    return mac_with_colons
