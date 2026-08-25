# MATKAP JADX connector notice

This binary is based on `zinja-coder/jadx-ai-mcp` commit
`d2dd72e6c0d84735b78773067075dac8cea651c1`, licensed under Apache License 2.0.
The upstream project is available at <https://github.com/zinja-coder/jadx-ai-mcp>.

MATKAP modifies `ResourceRoutes.java` so direct ZIP-backed text resources in the
currently open APK can be returned through the local, read-only resource route.
The modification enforces a 4 MiB size limit and rejects content with a high
control-character ratio. It does not execute APK content.

The complete upstream license is included as `LICENSE-jadx-ai-mcp.txt`.

