## Benchmarking

Run individual benchmark groups with the top-level bench harness:

```
cargo bench -p iron-key-bench --bench bench -- server_update_keys
cargo bench -p iron-key-bench --bench bench -- server_update_reg
cargo bench -p iron-key-bench --bench bench -- server_lookup
cargo bench -p iron-key-bench --bench bench -- client_lookup
cargo bench -p iron-key-bench --bench bench -- audit
```

Note: building the structured reference string (SRS) can take a while—please be patient during the first run.
