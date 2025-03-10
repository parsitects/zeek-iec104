signature dpd_iec104 {
    ip-proto == tcp
    payload /^\x68/
    enable "spicy_iec104"
}
