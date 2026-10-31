# Evidence and limitations

Publishing ports without an explicit host bind exposes services to all host interfaces under normal Docker defaults. A database port written as `5432:5432` is easy to mistake for a container-only connection.

## Scope and false-positive boundaries

This is a static Compose-file heuristic, not Docker runtime introspection. Daemon defaults, firewalls, host routes, container listeners, Compose interpolation, modes and per-host policies can change actual reachability. It does not parse multiple Compose overrides, network ranges or nonstandard mappings; it explicitly reports unresolved cases for review.

## Authoritative sources

- https://docs.docker.com/reference/compose-file/services/
- https://docs.docker.com/engine/network/port-publishing/
- https://docs.docker.com/compose/how-tos/networking/

## Output policy

Paths and structured labels only; never print values from secret/config keys. Reports are deterministic for a given input file.
