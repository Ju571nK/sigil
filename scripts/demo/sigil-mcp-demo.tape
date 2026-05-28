# vhs tape — record docs/sigil-mcp-demo.gif
# Run from the repo root:  vhs scripts/demo/sigil-mcp-demo.tape
Output docs/sigil-mcp-demo.gif

Require bash
Set Shell bash
Set Theme "Dracula"
Set FontSize 16
Set Width 1120
Set Height 840
Set Padding 26
Set TypingSpeed 55ms

Sleep 600ms
Type "bash scripts/demo/sigil-mcp-demo.sh | python3 scripts/demo/sanitize.py"
Sleep 500ms
Enter
Sleep 10s
Sleep 1500ms
