@test "Ping self (net 1 to 1)" {
    ./ipxping -c 2 00000001.00dead00010f.0000 00000001.00dead00010f.9086
}

@test "Ping self (net 1 to 2)" {
    ./ipxping -c 2 00000001.00dead00010f.0000 00000002.00dead00020f.9086
}

@test "Ping self (net 2 to 3)" {
    ./ipxping -c 2 00000002.00dead00020f.0000 00000003.00dead00030f.9086
}

@test "Ping self (net 3 to 1)" {
    ./ipxping -c 2 00000003.00dead00030f.0000 00000001.00dead00010f.9086
}

@test "Ping ipxhost001" {
    ./ipxping -c 2 00000001.00dead00010f.0000 00000001.00dead000101.9086
}

@test "Ping ipxhost002" {
    ./ipxping -c 2 00000002.00dead00020f.0000 00000002.00dead000202.9086
}

@test "Ping ipxhost003" {
    ./ipxping -c 2 00000003.00dead00030f.0000 00000003.00dead000303.9086
}
