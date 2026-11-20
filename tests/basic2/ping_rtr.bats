@test "Ping ipxhost001" {
    ./ipxping -c 2 00000001.00dead00010f.0000 00000001.00dead000101.9086
}

@test "Ping ipxhost002" {
    ./ipxping -c 2 00000002.00dead00020f.0000 00000002.00dead000202.9086
}

@test "Ping ipxhost003" {
    ./ipxping -c 2 00000003.00dead00030f.0000 00000003.00dead000303.9086
}
