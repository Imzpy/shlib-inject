# shlib-inject
shared library injection prototype

Run tracee app first:

```
$ LD_LIBRARY_PATH=. ./app
```

Then run injection:

```
$ sudo ./inject `pidof app`
```
