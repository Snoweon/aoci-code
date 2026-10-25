// Native fuzz targets for the readers of index bytes written by humans, agents,
// and older binaries: Parse over a whole index text, ValidateEntryLineWith over
// one candidate Entry line (with the S-quota header it is judged against), and
// ParseTags over one tag. Run one with
//
//	go test -run '^$' -fuzz '^FuzzParse$' -fuzztime=30s ./internal/index
//
// or every target through `make fuzz-smoke`. The seed corpus under
// testdata/fuzz carries lines of the repository's own aoci.code.txt.
package index

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParse pins what every consumer of a Document relies on: no panic on any
// text, every line retained once and in order, each Entry bound to the exact
// line it came from and lexed the same way by ParseEntryLine, a second parse of
// RawText that reproduces the first, warnings that are safe to embed in a JSON
// response, and relocation against several roots that never panics.
func FuzzParse(f *testing.F) {
	for _, rel := range []string{"indexes/cli_style.txt", "indexes/platform_style.txt"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", rel))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
	for _, seed := range []string{
		"",
		"\n",
		"#only a header\n",
		"====头====\r\n===头部索引===\r\n文件名[标签]: F:头部格式示例不应成为条目\r\n===头部索引完毕===\r\n===段 /r/x/===\r\na.go[T.T.5.T]: F:甲 | R:- | A:- | S:-\r\n====完====\r\n",
		"===段 /r/x/===\na.go[T.T.5.T]: F:1 | R:- | A:- | S:-\na.go[T.T.5.T]: F:2 | R:- | A:- | S:-\n",
		"===根 /r/===\nroot.txt[T.T.5.T]: F:- | R:- | A:- | S:-\n===子 /r/sub/===\ns.go[T.T.5.T]: F:- | R:- | A:- | S:-\n",
		"#===头部===\n===C:/aoci-test/===\nmain.go[XC9T]: F:入口 | R:- | A:- | S:-\n===子 C:/aoci-test/src/===\nutil.go[XC5T]: F:工具 | R:- | A:- | S:-\n",
		"\ufeff===代码/repo/===\na.go[X.Y.5.T]: F:功 | R:- | A:- | S:-\n",
		"\ufeff#头部说明\n===代码/repo/===\n",
		"===Sources/tmp/example project/repo/===\n[...id].jsx[WR7S]: F:route | R:- | A:- | S:-\n",
		"===/w/(x)/repo/===\na.go[IM7S]: F:a | R:- | A:- | S:-\n===/w/(x)/repo/sub/===\nb.go[IM7S]: F:b | R:- | A:- | S:-\n",
		"===/tmp/example project/repo/===\nx.go[IM7S]: F:x | R:- | A:- | S:-\n===/tmp/example/sub/===\ny.go[IM7S]: F:y | R:- | A:- | S:-\n",
		"===/repo/===\nx.go[IM7S]: F:x | R:- | A:- | S:-\n===/repo/===\nx.go[IM7S]: F:x again | R:- | A:- | S:-\n",
		"===/repo/===\nbroken[tag: F:no closing bracket colon\nalso [t]: not an entry\n  lead[T.T.5.T]: F:leading space\n",
		"===/repo/===\nws.go[WA9JM]: F:a | R:b | A:c | S1:第一段 | S2:第二段 | S:|[]<>\n",
		"=== note /repo/ (annotated) ===\nn.go[IM7S]: F:n | R:- | A:- | S:-\n",
		"===/a/ /b/===\nm.go[IM7S]: F:m | R:- | A:- | S:-\n",
		"#S配额: C9-8≤100 C3-1≤30\n===/repo/===\nq.go[IM9S]: F:q | R:- | A:- | S:" + strings.Repeat("长", 120) + "\n",
		"===/repo/===\n\v[T.T.5.T]: F:vertical tab name | R:- | A:- | S:-\n\u00a0[T.T.5.T]: F:no-break space name | R:- | A:- | S:-\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		doc, warnings := Parse(text)
		if doc == nil {
			t.Fatal("Parse returned a nil Document")
		}
		// Every leading BOM goes, not one: a doubled BOM is a concatenation
		// artifact, and stripping one would leave RawText starting with the
		// other, so Parse(RawText) could not be a fixed point (seed d03d5667d745b3ab).
		normalized := strings.ReplaceAll(strings.TrimLeft(text, "\ufeff"), "\r\n", "\n")
		if doc.RawText != normalized {
			t.Fatalf("RawText is not the BOM-stripped LF text: %q", doc.RawText)
		}
		lines := strings.Split(normalized, "\n")

		rebuilt := append([]string{}, doc.HeaderLines...)
		for _, section := range doc.Sections {
			rebuilt = append(rebuilt, section.RawLines...)
		}
		if strings.Join(rebuilt, "\n") != normalized {
			t.Fatalf("lines were not retained losslessly: %q", rebuilt)
		}

		for _, section := range doc.Sections {
			if section.StartLine < 1 || section.StartLine > len(lines) {
				t.Fatalf("section StartLine %d outside %d lines", section.StartLine, len(lines))
			}
			if len(section.RawLines) == 0 || section.RawLines[0] != section.HeaderLine ||
				lines[section.StartLine-1] != section.HeaderLine {
				t.Fatalf("section header %q is not the line at %d", section.HeaderLine, section.StartLine)
			}
			if section.AbsPath == "" && len(section.Entries) != 0 {
				t.Fatalf("separator section %q collected %d Entries", section.HeaderLine, len(section.Entries))
			}
			if section.AbsPath != "" && !strings.HasPrefix(section.AbsPath, section.LegacyAbsPath) {
				t.Fatalf("extended path %q does not extend the legacy path %q", section.AbsPath, section.LegacyAbsPath)
			}
			for _, entry := range section.Entries {
				if entry.LineNo < 1 || entry.LineNo > len(lines) || lines[entry.LineNo-1] != entry.FullLine {
					t.Fatalf("Entry %q is not the line at %d", entry.FullLine, entry.LineNo)
				}
				if entry.Filename == "" || entry.Filename != strings.TrimSpace(entry.Filename) {
					t.Fatalf("Entry at %d has file name %q", entry.LineNo, entry.Filename)
				}
				again, ok := ParseEntryLine(entry.FullLine, entry.LineNo)
				if !ok {
					t.Fatalf("ParseEntryLine rejects a line Parse accepted: %q", entry.FullLine)
				}
				if again.Filename != entry.Filename || again.TagsRaw != entry.TagsRaw || again.F != entry.F ||
					again.R != entry.R || again.Api != entry.Api || again.S != entry.S ||
					!reflect.DeepEqual(again.TagsParsed, entry.TagsParsed) {
					t.Fatalf("ParseEntryLine and Parse disagree on %q: %+v vs %+v", entry.FullLine, again, entry)
				}
				if !reflect.DeepEqual(ParseTags(entry.TagsRaw), entry.TagsParsed) {
					t.Fatalf("TagsParsed is not ParseTags(TagsRaw) for %q", entry.FullLine)
				}
			}
		}
		for _, line := range lines {
			nameEnd, tagStart, tagEnd, ok := EntryTagSpan(line)
			if !ok {
				continue
			}
			if nameEnd < 0 || nameEnd+1 != tagStart || tagStart > tagEnd || tagEnd >= len(line) ||
				line[nameEnd] != '[' || line[tagEnd] != ']' {
				t.Fatalf("EntryTagSpan(%q) = %d,%d,%d is not a bracketed span", line, nameEnd, tagStart, tagEnd)
			}
		}

		for _, warning := range warnings {
			if warning.LineNo < 1 || warning.LineNo > len(lines) {
				t.Fatalf("warning line %d outside %d lines: %q", warning.LineNo, len(lines), warning.Msg)
			}
			if warning.Msg == "" || !utf8.ValidString(warning.Msg) {
				t.Fatalf("warning at %d is empty or not valid UTF-8: %q", warning.LineNo, warning.Msg)
			}
		}

		// The CRLF fold is one pass, so a "\r\r\n" ending keeps its first "\r"
		// as line content and leaves a "\r\n" in RawText; such text is not a
		// fixed point of the fold and a second parse legitimately folds again.
		if !strings.Contains(doc.RawText, "\r\n") {
			second, secondWarnings := Parse(doc.RawText)
			if !reflect.DeepEqual(second, doc) {
				t.Fatalf("parsing RawText again changed the Document")
			}
			if !reflect.DeepEqual(secondWarnings, warnings) {
				t.Fatalf("parsing RawText again changed the warnings: %+v vs %+v", secondWarnings, warnings)
			}
		}

		for _, root := range []string{"/repo", "/r", `C:\aoci-test`, "/w/(x)/repo", "/tmp/example project/repo", "/", ""} {
			ResolveRelPaths(doc, root)
			for _, section := range doc.Sections {
				for _, entry := range section.Entries {
					rel := entry.RelPath
					if rel == "" {
						continue
					}
					if rel != path.Clean(rel) && rel != path.Clean(strings.TrimSuffix(rel, "/"))+"/" {
						t.Fatalf("RelPath %q under root %q is not clean", rel, root)
					}
				}
			}
			_ = FindSectionForPath(doc, root, "a/b.go")
			_ = FindSectionForPath(doc, root, "x.go")
			_ = FindEntry(doc, "a/b.go")
			_ = FindEntriesByFilename(doc, "b.go")
		}
	})
}

// FuzzValidateEntryLine pins the write-side gate for one candidate line judged
// against an arbitrary header: no panic, a deterministic verdict made only of
// error and warning levels, every structurally unusable line refused, and for
// an accepted line agreement with the lexer (same base name as the target
// path) and with ParseTags (the P-15 warning fires exactly when the tag does
// not parse). The header reader ExtractSQuotaThresholds is exercised on the
// same input.
func FuzzValidateEntryLine(f *testing.F) {
	for _, seed := range [][3]string{
		{"a/b.go", "b.go[X.Y.5.T]: F:功 | R:- | A:- | S:当前态", ""},
		{"a/dir/", "dir/[X.Y.5.T]: F:目录 | R:- | A:- | S:-", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:实现依赖求解并提供兼容入口 | R:- | A:- | S:-", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:- | R:- | A:- | S:-", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:- | R:- | A:- | S:1\n2", ""},
		{"a/b.go", "   ", ""},
		{"a/b.go", "这不是条目", ""},
		{"a/b.go", "c.go[X.Y.5.T]: F:- | R:- | A:- | S:-", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:- | R:-", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:- | R:- | A:- | S:本次修改改为新版", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:功 | R:x.go | R:y.go | R:z.go | A:- | S:当前态", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:一 | F:二 | R:- | A:- | S:当前态", ""},
		{"a/b.go", "b.go[X.Y.5.T]: F:功 | R:- | A:- | S1:一 | S2:二", ""},
		{"a/b.go", "b.go[UAU8]: F:功 | R:- | A:- | S:当前态", ""},
		{"a/b.go", "b.go[MM7]: F:功 | R:- | A:- | S:当前态", ""},
		{"a/b.go", "b.go[WA9JM]: F:功 | R:- | A:- | S:当前态", ""},
		{"a/b.go", "b.go[X.Y.5]: F:功 | R:- | A:- | S:当前态", ""},
		{"f.go", "f.go[I,CL,C8,EL]: F:x | R:- | A:- | S:-", ""},
		{"app/[...id].jsx", "[...id].jsx[WR7S]: F:route | R:- | A:- | S:-", ""},
		{"a/b.go", "b.go[IM9S]: F:q | R:- | A:- | S:" + strings.Repeat("长", 120), "#S配额: C9-8≤100 C3-1≤30\n"},
		{"a/b.go", "b.go[IM9S]: F:q | R:- | A:- | S:" + strings.Repeat("长", 120), "#S配额: C9-8<=100 C3-1<=30\n"},
		{"a/b.go", "b.go[IM3S]: F:q | R:- | A:- | S:short", "# S配额: C9-8≤100字 C3-1≤30字\n"},
		{"a/b.go", "b.go[IM3S]: F:q | R:- | A:- | S:short", "#S配额(字数上限)： C9-C8≤100 C3-C1≤30\n"},
		{"a\\b.go", "b.go[X.Y.5.T]: F:- | R:- | A:- | S:-\r", "#S配额: nonsense\n"},
		{"a/b.go", "\v[X.Y.5.T]: F:- | R:- | A:- | S:-", ""},
		{"", "", ""},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}

	f.Fuzz(func(t *testing.T, relPath, line, header string) {
		thresholds := ExtractSQuotaThresholds(header)
		_ = EffectiveSQuotaContract(header)
		if thresholds != nil {
			for c := -1; c <= 10; c++ {
				thresholds.LimitForC(c)
			}
			thresholds.HasQuotas()
			thresholds.SawSQuotaLine()
			thresholds.UnrecognizedName()
		}

		first := ValidateEntryLineWith(relPath, line, thresholds)
		if second := ValidateEntryLineWith(relPath, line, thresholds); !reflect.DeepEqual(first, second) {
			t.Fatalf("verdict is not deterministic: %+v vs %+v", first, second)
		}
		for _, violation := range first {
			if violation.Level != LevelError && violation.Level != LevelWarning {
				t.Fatalf("unknown violation level %q", violation.Level)
			}
			if violation.Msg == "" {
				t.Fatalf("violation without a message: %+v", violation)
			}
		}
		if strings.Contains(line, "\n") || strings.TrimSpace(line) == "" {
			if !HasError(first) {
				t.Fatalf("multi-line or blank line was not refused: %q", line)
			}
			return
		}
		entry, ok := ParseEntryLine(line, 1)
		if !ok {
			if !HasError(first) {
				t.Fatalf("line the lexer rejects was not refused: %q", line)
			}
			return
		}
		if HasError(first) {
			return
		}
		wantBase := path.Base(strings.TrimSuffix(strings.ReplaceAll(relPath, "\\", "/"), "/"))
		gotBase := path.Base(strings.TrimSuffix(entry.Filename, "/"))
		if wantBase != gotBase {
			t.Fatalf("accepted %q for %q although the base names differ", line, relPath)
		}
		if HasTagParseWarning(first) != (len(ParseTags(entry.TagsRaw)) == 0) {
			t.Fatalf("tag-parse warning and ParseTags disagree on %q: %+v", entry.TagsRaw, first)
		}
	})
}

// FuzzParseTags pins the two legal tag forms and the comma refusal: the result
// is empty or carries non-blank A, B, C, and E (D optional), a comma in any
// width yields nothing, and the parsed dimensions concatenate (compact form) or
// join with dots (dotted form) back to the trimmed input.
func FuzzParseTags(f *testing.F) {
	for _, seed := range []string{
		"WA9JM", "Index.Types.9.S", "FS.Paths.9.Xp.S", "I,CL,C8,EL", "I.CL,C8.EL", "I，CL，C8，EL", "IC8,T",
		"UAU8", "MM7", "X.Y.5", "X.Y.5.T", "IM7S", "CG3T", "", " ", "A1", "A1B", "1AB", "AB1", "a.b.c.d.e.f",
		"..", "A..9.S", "标签9规", "T.T.5.T", "XC9T", "WR7S", "ID1S", "A.B.C.D.E", " WA9JM ", "W\u00a09M",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := ParseTags(raw)
		if got == nil {
			t.Fatal("ParseTags returned a nil map")
		}
		trimmed := strings.TrimSpace(raw)
		if len(got) == 0 {
			return
		}
		if strings.ContainsAny(trimmed, ",，") {
			t.Fatalf("comma tag %q parsed to %v", raw, got)
		}
		for key := range got {
			if key != "A" && key != "B" && key != "C" && key != "D" && key != "E" {
				t.Fatalf("unknown dimension %q in %v", key, got)
			}
		}
		for _, key := range []string{"A", "C", "E"} {
			if strings.TrimSpace(got[key]) == "" {
				t.Fatalf("dimension %s blank in %v for %q", key, got, raw)
			}
		}
		// The dotted form refuses a blank segment; the compact form only refuses
		// an empty B, so a whitespace B survives here and is left to the
		// dictionary gate.
		if got["B"] == "" {
			t.Fatalf("dimension B empty in %v for %q", got, raw)
		}
		if strings.Contains(trimmed, ".") {
			if strings.TrimSpace(got["B"]) == "" {
				t.Fatalf("dotted dimension B blank in %v for %q", got, raw)
			}
			parts := []string{got["A"], got["B"], got["C"]}
			if d, ok := got["D"]; ok {
				parts = append(parts, d)
			}
			parts = append(parts, got["E"])
			if len(parts) != 4 && len(parts) != 5 {
				t.Fatalf("dotted tag %q parsed to %d segments: %v", raw, len(parts), got)
			}
			if strings.Join(parts, ".") != trimmed {
				t.Fatalf("dotted dimensions %v do not rebuild %q", got, trimmed)
			}
			return
		}
		if len(got["C"]) != 1 || got["C"][0] < '0' || got["C"][0] > '9' {
			t.Fatalf("compact importance %q is not one digit for %q", got["C"], raw)
		}
		// The compact reader works on runes, so bytes that are not UTF-8 come
		// back as U+FFFD; compare against the same reading of the input.
		if got["A"]+got["B"]+got["C"]+got["D"]+got["E"] != string([]rune(trimmed)) {
			t.Fatalf("compact dimensions %v do not rebuild %q", got, trimmed)
		}
		if strings.ContainsAny(got["A"]+got["B"], "0123456789") {
			t.Fatalf("a digit before the importance digit in %v for %q", got, raw)
		}
	})
}
