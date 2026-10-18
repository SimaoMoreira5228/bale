# BALE codec benchmark

- date: 2026-10-18T14:45:23+00:00
- machine: Intel(R) Xeon(R) CPU E5-2690 v3 @ 2.60GHz (24 logical CPUs, Linux-7.2.11-200.fc44.x86_64-x86_64-with-glibc2.43)
- governor: performance, SMT active: 1, pinned CPU: 5
- load average at start: (1.544921875, 2.2861328125, 1.11669921875)
- corpus: 7bcddc28a3846c3ac37c04975aa80ff2f029f03a62c596451d1e3442fbebe952
- commit: 7623c39724f4440238d3141388ec3e637167e97f, chunk size 1048576, 3 runs

Codec rows compare identical fixed chunks with deduplication disabled. Stored bytes include
BALE record overhead and per-chunk raw fallback.

## size-100M

| codec | stored MiB | ratio | raw fallback | encode MB/s median [min-max] | decode MB/s median [min-max] | peak RSS KiB |
|---|---:|---:|---:|---|---|---:|
| raw | 100.0 | 1.0001 | 100/100 | 15354.2 [15309.8-15357.2] | 15318.6 [15114.4-15661.9] | 7328 |
| lz4:0 | 72.7 | 0.7267 | 32/100 | 610.6 [605.7-613.0] | 3424.6 [3392.9-3428.1] | 7648 |
| lz4:1 | 72.7 | 0.7267 | 32/100 | 601.7 [586.7-612.8] | 3357.7 [3189.1-3440.3] | 7644 |
| lz4:9 | 60.6 | 0.6064 | 32/100 | 12.8 [12.6-12.8] | 4474.2 [4225.1-4571.9] | 7976 |
| zstd:1 | 46.0 | 0.4597 | 7/100 | 340.9 [327.1-342.5] | 1026.9 [985.8-1027.8] | 8168 |
| zstd:3 | 41.9 | 0.4195 | 7/100 | 197.3 [196.1-197.4] | 883.6 [877.7-891.1] | 8868 |

## End to end, deduplication enabled

Throughput is input bytes over the median time, which includes reading the input and
writing the output.

| target | input MiB | preset | archive MiB | ratio | create MB/s | create s median [min-max] | extract MB/s | extract s median [min-max] | create RSS KiB | extract RSS KiB |
|---|---:|---|---:|---:|---:|---|---:|---|---:|---:|
| size-100M | 100.0 | raw | 100.0 | 1.0002 | 1323.5 | 0.079 [0.079-0.080] | 1304.5 | 0.080 [0.079-0.081] | 5720 | 6064 |
| size-100M | 100.0 | lz4:0 | 72.7 | 0.7268 | 428.2 | 0.245 [0.244-0.249] | 1017.1 | 0.103 [0.102-0.104] | 7056 | 7400 |
| size-100M | 100.0 | lz4:1 | 72.7 | 0.7268 | 406.1 | 0.258 [0.255-0.261] | 980.2 | 0.107 [0.105-0.108] | 7064 | 7304 |
| size-100M | 100.0 | lz4:9 | 60.6 | 0.6065 | 12.2 | 8.599 [8.534-8.879] | 1105.3 | 0.095 [0.095-0.095] | 7256 | 7380 |
| size-100M | 100.0 | zstd:1 | 46.0 | 0.4598 | 270.8 | 0.387 [0.386-0.394] | 587.3 | 0.179 [0.178-0.179] | 7768 | 7980 |
| size-100M | 100.0 | zstd:3 | 42.0 | 0.4196 | 169.8 | 0.617 [0.616-0.618] | 543.7 | 0.193 [0.192-0.195] | 8592 | 8368 |
