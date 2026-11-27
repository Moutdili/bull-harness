"""HexStrike arsenal behind three meta-tools (tools_list, tool_help, tool_run), stdio MCP, stdlib only.

Origin: HexStrike AI (MIT, Copyright (c) 2026 Muhammad Osama (0x4m4)), hexstrike_mcp.py lines 267-5414
(`setup_mcp_server`, the 151 `@mcp.tool()` functions). Modified: the tool table is rewritten as data (registry.py),
commands are argv lists run without any shell (run.py), no HTTP server, no Flask; the MCP loop is our own (server.py).

  registry.py  TOOLS: one entry per HexStrike tool, classed (passive, mapper, scanner, local, no-route, refused)
  run.py       tools_list / tool_help / tool_run: validation of every argument, then subprocess without a shell
  server.py    main(argv): MCP over stdio, one JSON-RPC message per line
"""
