## HAProxy OpenTelemetry Filter (OTel)

The OTel filter enables HAProxy to emit telemetry data -- traces, metrics and
logs -- to any OpenTelemetry-compatible backend via the OpenTelemetry protocol
(OTLP).

It is the successor to the OpenTracing (OT) filter, built on the OpenTelemetry
standard which unifies distributed tracing, metrics and logging into a single
observability framework.

### Features

- **Distributed tracing** -- spans with parent-child relationships, context
  propagation via HTTP headers or HAProxy variables, links, baggage and status.
- **Metrics** -- counter, histogram, up-down counter and gauge instruments with
  configurable aggregation and bucket boundaries.
- **Logging** -- log records with severity levels, optional span correlation and
  runtime-evaluated attributes.
- **Rate limiting** -- percentage-based sampling (0.0--100.0) for controlling
  overhead.
- **ACL integration** -- fine-grained conditional execution at instrumentation,
  scope and event levels.
- **CLI management** -- runtime enable/disable, rate adjustment, error mode
  switching and status inspection.
- **Context propagation** -- inject/extract span contexts between cascaded
  HAProxy instances or external services.

### Dependencies

The filter requires the
[OpenTelemetry C Wrapper](https://github.com/haproxytech/opentelemetry-c-wrapper)
library, which wraps the OpenTelemetry C++ SDK.

### Building

The OTel filter is compiled together with HAProxy by adding `USE_OTEL=1` to the
make command.

#### Using pkg-config

```
PKG_CONFIG_PATH=/opt/lib/pkgconfig make -j8 USE_OTEL=1 TARGET=linux-glibc
```

#### Explicit paths

```
make -j8 USE_OTEL=1 OTEL_INC=/opt/include OTEL_LIB=/opt/lib TARGET=linux-glibc
```

#### Build options

| Variable        | Description                                         |
|-----------------|-----------------------------------------------------|
| `USE_OTEL`      | Enable the OpenTelemetry filter                     |
| `OTEL_DEBUG`    | Compile in debug mode                               |
| `OTEL_INC`      | Force path to opentelemetry-c-wrapper include files |
| `OTEL_LIB`      | Force path to opentelemetry-c-wrapper library       |
| `OTEL_RUNPATH`  | Add opentelemetry-c-wrapper RUNPATH to executable   |
| `OTEL_USE_VARS` | Enable context propagation via HAProxy variables    |

#### Debug mode

```
PKG_CONFIG_PATH=/opt/lib/pkgconfig make -j8 USE_OTEL=1 OTEL_DEBUG=1 TARGET=linux-glibc
```

#### Variable-based context propagation

```
PKG_CONFIG_PATH=/opt/lib/pkgconfig make -j8 USE_OTEL=1 OTEL_USE_VARS=1 TARGET=linux-glibc
```

#### Verifying the build

```
./haproxy -vv | grep -i opentelemetry
```

If the filter is built in, the output contains:

```
Built with OpenTelemetry support (C++ version 1.26.0, C Wrapper version 1.0.0-842).
	[OTEL] opentelemetry
```

#### Library path at runtime

When pkg-config is not used, the executable may not find the library at startup.
Use `LD_LIBRARY_PATH` or build with `OTEL_RUNPATH=1`:

```
LD_LIBRARY_PATH=/opt/lib ./haproxy ...
```

```
make -j8 USE_OTEL=1 OTEL_RUNPATH=1 OTEL_INC=/opt/include OTEL_LIB=/opt/lib TARGET=linux-glibc
```

### Configuration

The filter uses a two-file configuration model:

1. **OTel configuration file** (`.cfg`) -- defines the telemetry model:
   instrumentation settings, scopes and groups.
2. **YAML configuration file** (`.yml`) -- defines the OpenTelemetry SDK
   pipeline: exporters, samplers, processors, providers and signal routing.

#### Activating the filter

Add the filter to a HAProxy proxy section (frontend/listen/backend):

```
frontend my-frontend
    ...
    filter opentelemetry [id <id>] config <file>
    ...
```

If no filter id is specified, `otel-filter` is used as default.

#### OTel configuration file structure

The OTel configuration file contains three section types:

- `otel-instrumentation` -- mandatory; references the YAML file, sets rate
  limits, error modes, logging and declares groups and scopes.
- `otel-scope` -- defines actions (spans, attributes, metrics, logs) triggered
  by stream events or from groups.
- `otel-group` -- a named collection of scopes triggered from HAProxy TCP/HTTP
  rules.

#### Minimal YAML configuration

```yaml
exporters:
  my_exporter:
    type:     otlp_http
    endpoint: "http://localhost:4318/v1/traces"

samplers:
  my_sampler:
    type: always_on

processors:
  my_processor:
    type: batch

providers:
  my_provider:
    resources:
      - service.name: "haproxy"

signals:
  traces:
    scope_name: "HAProxy OTel"
    exporters:  my_exporter
    samplers:   my_sampler
    processors: my_processor
    providers:  my_provider
```

#### Supported YAML exporters

| Type            | Description                           |
|-----------------|---------------------------------------|
| `otlp_grpc`     | OTLP over gRPC                        |
| `otlp_http`     | OTLP over HTTP (JSON or Protobuf)     |
| `otlp_file`     | Local files in OTLP format            |
| `zipkin`        | Zipkin-compatible backends            |
| `elasticsearch` | Elasticsearch                         |
| `ostream`       | Text output to a file (for debugging) |
| `memory`        | In-memory buffer (for testing)        |

### Scope keywords

| Keyword        | Description                                             |
|----------------|---------------------------------------------------------|
| `span`         | Create or reference a span                              |
| `attribute`    | Set key-value span attributes                           |
| `event`        | Add timestamped span events                             |
| `baggage`      | Set context propagation data                            |
| `status`       | Set span status (ok/error/ignore/unset)                 |
| `link`         | Add span links to related spans                         |
| `inject`       | Inject context into headers or variables                |
| `extract`      | Extract context from headers or variables               |
| `finish`       | Close spans (supports wildcards: `*`, `*req*`, `*res*`) |
| `instrument`   | Create or update metric instruments                     |
| `log-record`   | Emit a log record with severity                         |
| `otel-event`   | Bind scope to a filter event with optional ACL          |
| `idle-timeout` | Set periodic event interval for idle streams            |

### CLI commands

Available via the HAProxy CLI socket (prefix: `flt-otel`):

| Command                    | Description                        |
|----------------------------|------------------------------------|
| `flt-otel status`          | Show filter status                 |
| `flt-otel enable`          | Enable the filter                  |
| `flt-otel disable`         | Disable the filter                 |
| `flt-otel hard-errors`     | Enable hard-errors mode            |
| `flt-otel soft-errors`     | Disable hard-errors mode           |
| `flt-otel logging [state]` | Set logging state                  |
| `flt-otel rate [value]`    | Set or show the rate limit         |
| `flt-otel debug [level]`   | Set debug level (debug build only) |

When invoked without arguments, `rate`, `logging` and `debug` display the
current value.

### Performance

Benchmark results from the standalone (`sa`) configuration, which exercises all
events (worst-case scenario):

| Rate limit | Req/s  | Avg latency | Overhead |
|------------|--------|-------------|----------|
| 100.0%     | 38,202 | 213.08 us   | 21.6%    |
| 50.0%      | 42,777 | 190.49 us   | 12.2%    |
| 25.0%      | 45,302 | 180.46 us   | 7.0%     |
| 10.0%      | 46,879 | 174.69 us   | 3.7%     |
| 2.5%       | 47,993 | 170.58 us   | 1.4%     |
| disabled   | 48,788 | 167.74 us   | ~0       |
| off        | 48,697 | 168.00 us   | baseline |

With a rate limit of 10% or less, the performance impact is negligible.
Detailed methodology and additional results are in the `test/` directory.

### Test configurations

The `test/` directory contains ready-to-run example configurations:

- **sa** -- standalone; the most comprehensive example, demonstrating spans,
  attributes, events, links, baggage, status, metrics, log records, ACL
  conditions and idle-timeout events.
- **fe/be** -- distributed tracing across two cascaded HAProxy instances using
  HTTP header-based context propagation.
- **ctx** -- context propagation via HAProxy variables using the inject/extract
  mechanism.
- **cmp** -- minimal configuration for benchmarking comparison.
- **empty** -- filter initialized with no active telemetry.

#### Quick start with Jaeger

Start a Jaeger all-in-one container:

```
docker run -d --name jaeger -p 4317:4317 -p 4318:4318 -p 16686:16686 jaegertracing/all-in-one:latest
```

Run one of the test configurations:

```
./test/run-sa.sh
```

Open the Jaeger UI at `http://localhost:16686` to view traces.

### Documentation

Detailed documentation is available in the following files:

- [README](README) -- complete reference documentation
- [README-configuration](README-configuration) -- configuration guide
- [README-conf](README-conf) -- configuration details
- [README-design](README-design) -- cross-cutting design patterns
- [README-implementation](README-implementation) -- component architecture
- [README-func](README-func) -- function reference
- [README-misc](README-misc) -- miscellaneous notes

### Copyright

Copyright 2026 HAProxy Technologies

### Author

Miroslav Zagorac <mzagorac@haproxy.com>
