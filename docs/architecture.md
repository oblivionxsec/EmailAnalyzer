# Architecture

EmailAnalyzer separates the offline analysis engine from the static report viewer.

See the repository README for the processing flow and component boundaries.

The static viewer is deliberately untrusted/public code: it performs local report review only and has no credentials. Network-backed enrichment belongs outside the viewer, in a private local CLI or separately protected service.

Optional local analyzers receive attachment bytes in memory and write evidence under each attachment's `local_analysis` field. Private payload bytes are removed before JSON serialization; no local-tool adapter sends content over the network.
