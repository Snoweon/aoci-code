package cognitionbudget

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aoci-spec/aoci-code/internal/index"
	"github.com/aoci-spec/aoci-code/internal/machinecontract"
)

// sCoverageEntry is one fixture Entry: its C Importance and the S it was
// authored with. Every expectation below is derived from this table by
// counting, never written down a second time.
type sCoverageEntry struct {
	importance int
	s          string
}

var sCoverageFixture = []sCoverageEntry{
	{9, "Nine guards the boundary"},
	{9, "-"},
	{8, "Eight keeps the invariant"},
	{8, "-"},
	{8, "-"},
	{7, "Seven names the trap"},
	{7, "-"},
	{5, "Five explains the retry"},
	{5, "-"},
	{3, "-"},
}

func sCoverageIndex(entries []sCoverageEntry) []byte {
	var builder strings.Builder
	builder.WriteString("# header\n===/repo/===\n")
	for position, entry := range entries {
		fmt.Fprintf(&builder, "entry-%03d.go[C.RT.%d.T]: F:core | R:- | A:- | S:%s\n", position, entry.importance, entry.s)
	}
	return []byte(builder.String())
}

// expectedSCoverage counts the fixture the way a reader would by hand: one
// row per normalized policy S band, plus the high-importance headline.
func expectedSCoverage(t *testing.T, policy Policy, entries []sCoverageEntry) (bands []SCoverageBand, highEntries, highAbsent, percent int) {
	t.Helper()
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	bands = []SCoverageBand{}
	for _, band := range normalized.S {
		bands = append(bands, SCoverageBand{MinC: band.MinC, MaxC: band.MaxC})
	}
	for _, entry := range entries {
		present := entry.s != "-"
		for position := range bands {
			if entry.importance >= bands[position].MinC && entry.importance <= bands[position].MaxC {
				bands[position].Entries++
				if present {
					bands[position].SPresent++
				}
			}
		}
		if entry.importance >= machinecontract.HighImportanceMinC {
			highEntries++
			if !present {
				highAbsent++
			}
		}
	}
	if highEntries > 0 {
		percent = highAbsent * 100 / highEntries
	}
	return bands, highEntries, highAbsent, percent
}

func TestBuildReportsSCoveragePerBandAndHighImportance(t *testing.T) {
	policy := DefaultPolicy(machinecontract.BudgetModeObserve)
	wantBands, wantEntries, wantAbsent, wantPercent := expectedSCoverage(t, policy, sCoverageFixture)
	if wantAbsent == 0 || wantAbsent == wantEntries {
		t.Fatalf("fixture premise: high-importance Entries must mix present and absent S, got %d/%d absent", wantAbsent, wantEntries)
	}
	report, err := Build("/repo", sCoverageIndex(sCoverageFixture), policy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.SCoverage, wantBands) {
		t.Fatalf("S coverage bands\n got %+v\nwant %+v", report.SCoverage, wantBands)
	}
	if report.HighImportanceEntries != wantEntries || report.HighImportanceSAbsent != wantAbsent || report.HighImportanceSAbsentPercent != wantPercent {
		t.Fatalf("high-importance headline got %d/%d (%d%%) want %d/%d (%d%%)", report.HighImportanceSAbsent,
			report.HighImportanceEntries, report.HighImportanceSAbsentPercent, wantAbsent, wantEntries, wantPercent)
	}
	counted := 0
	for _, band := range report.SCoverage {
		counted += band.Entries
	}
	if counted != report.EntryCount || counted != len(sCoverageFixture) {
		t.Fatalf("bands counted %d Entries, report has %d, fixture has %d", counted, report.EntryCount, len(sCoverageFixture))
	}
}

func TestSCoveragePercentIsZeroWithoutHighImportanceEntries(t *testing.T) {
	low := []sCoverageEntry{}
	for _, entry := range sCoverageFixture {
		if entry.importance < machinecontract.HighImportanceMinC {
			low = append(low, entry)
		}
	}
	if len(low) == 0 {
		t.Fatal("fixture premise: some Entries must sit below the high-importance floor")
	}
	policy := DefaultPolicy(machinecontract.BudgetModeObserve)
	wantBands, _, _, _ := expectedSCoverage(t, policy, low)
	report, err := Build("/repo", sCoverageIndex(low), policy)
	if err != nil {
		t.Fatal(err)
	}
	if report.HighImportanceEntries != 0 || report.HighImportanceSAbsent != 0 || report.HighImportanceSAbsentPercent != 0 {
		t.Fatalf("no high-importance Entries must report 0/0 and 0%%: %+v", report)
	}
	if !reflect.DeepEqual(report.SCoverage, wantBands) {
		t.Fatalf("low-importance Entries still fill their bands\n got %+v\nwant %+v", report.SCoverage, wantBands)
	}
}

func TestRebindWholeIndexTokensKeepsSCoverage(t *testing.T) {
	policy := DefaultPolicy(machinecontract.BudgetModeObserve)
	report, err := Build("/repo", sCoverageIndex(sCoverageFixture), policy)
	if err != nil {
		t.Fatal(err)
	}
	before := *report
	if err := report.RebindWholeIndexTokens(policy.WholeIndex.MaxTokens+1, policy); err != nil {
		t.Fatal(err)
	}
	if report.Status != machinecontract.BudgetStatusExceeded {
		t.Fatalf("rebind did not recompute status: %s", report.Status)
	}
	if !reflect.DeepEqual(report.SCoverage, before.SCoverage) || report.HighImportanceEntries != before.HighImportanceEntries ||
		report.HighImportanceSAbsent != before.HighImportanceSAbsent || report.HighImportanceSAbsentPercent != before.HighImportanceSAbsentPercent {
		t.Fatalf("rebind changed S coverage\n got %+v\nwant %+v", *report, before)
	}
}

func TestHighImportanceSAbsentHintFiresExactlyAtThreshold(t *testing.T) {
	threshold := machinecontract.HighImportanceSAbsentHintPercent
	for _, testCase := range []struct {
		name    string
		entries int
		percent int
		want    bool
	}{
		{"no high-importance Entries never hint", 0, 100, false},
		{"one below threshold", 1, threshold - 1, false},
		{"exactly at threshold", 1, threshold, true},
		{"one above threshold", 1, threshold + 1, true},
		{"everything absent", 1, 100, true},
	} {
		if got := HighImportanceSAbsentHint(testCase.entries, testCase.percent); got != testCase.want {
			t.Fatalf("%s: entries=%d percent=%d hint=%v want %v", testCase.name, testCase.entries, testCase.percent, got, testCase.want)
		}
	}
}

// The rule is also pinned through Build so a tally that rounds differently
// from the constant cannot pass the unit table above and still mis-hint.
func TestBuiltReportHintsExactlyAtThresholdShare(t *testing.T) {
	threshold := machinecontract.HighImportanceSAbsentHintPercent
	policy := DefaultPolicy(machinecontract.BudgetModeObserve)
	build := func(absent int) *Report {
		entries := []sCoverageEntry{}
		for position := 0; position < 100; position++ {
			s := "Present S text"
			if position < absent {
				s = "-"
			}
			entries = append(entries, sCoverageEntry{machinecontract.HighImportanceMinC, s})
		}
		report, err := Build("/repo", sCoverageIndex(entries), policy)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	at := build(threshold)
	if at.HighImportanceSAbsentPercent != threshold || !HighImportanceSAbsentHint(at.HighImportanceEntries, at.HighImportanceSAbsentPercent) {
		t.Fatalf("%d of 100 absent must hint: percent=%d", threshold, at.HighImportanceSAbsentPercent)
	}
	below := build(threshold - 1)
	if below.HighImportanceSAbsentPercent != threshold-1 || HighImportanceSAbsentHint(below.HighImportanceEntries, below.HighImportanceSAbsentPercent) {
		t.Fatalf("%d of 100 absent must not hint: percent=%d", threshold-1, below.HighImportanceSAbsentPercent)
	}
}

func TestSPresentTreatsDashAndEmptyAsAbsent(t *testing.T) {
	for _, absent := range []string{"", "-", " - ", "   "} {
		if SPresent(absent) {
			t.Fatalf("%q counted as present S", absent)
		}
	}
	if !SPresent("Removal preserves the retention boundary") {
		t.Fatal("authored S counted as absent")
	}
}

func TestSummaryCarriesSCoverageClause(t *testing.T) {
	policy := DefaultPolicy(machinecontract.BudgetModeObserve)
	_, wantEntries, wantAbsent, _ := expectedSCoverage(t, policy, sCoverageFixture)
	report, err := Build("/repo", sCoverageIndex(sCoverageFixture), policy)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("S coverage: C%d+ %d/%d have S", machinecontract.HighImportanceMinC, wantEntries-wantAbsent, wantEntries)
	if summary := Summary(report); !strings.Contains(summary, want) || !strings.Contains(summary, "whole_index=") {
		t.Fatalf("summary %q lacks %q or the budget figures", summary, want)
	}
}

func TestFormatSCoverageBandsLabelsSingleAndRangedBands(t *testing.T) {
	got := FormatSCoverageBands([]SCoverageBand{{MinC: 1, MaxC: 4, Entries: 30, SPresent: 12}, {MinC: 9, MaxC: 9, Entries: 1, SPresent: 1}})
	if got != "C1-4 12/30, C9 1/1" {
		t.Fatalf("band rendering: %q", got)
	}
	if FormatSCoverageBands(nil) != "" {
		t.Fatal("empty band list must render empty")
	}
}

// The S hard limit is the Meta rune quota (#146): one CJK rune is three bytes
// and therefore one token, so a band below the quota rejected what the
// authoring contract permitted. The band is floored by the quota, a looser
// declaration raises the floor, a band raised above the quota still binds,
// and R keeps its band untouched.
func TestSFieldHardLimitIsFlooredByTheRuneQuota(t *testing.T) {
	policy := DefaultPolicy(machinecontract.BudgetModeEnforce)
	entry := func(s string) string { return "a.go[CG9T]: F:f | R:- | A:- | S:" + s }
	// 210 runes = 630 bytes = 210 tokens: over the C9 band (200), inside the quota (600).
	if violations := ValidateEntry(entry(strings.Repeat("约", 210)), policy); len(violations) != 0 {
		t.Fatalf("S within its rune quota must not be a budget violation: %+v", violations)
	}
	// 1000 ASCII runes = 333 tokens: over the band, over the quota in runes; the
	// rune gate owns that refusal and the budget stays silent.
	if violations := ValidateEntry(entry(strings.Repeat("s", 1000)), policy); len(violations) != 0 {
		t.Fatalf("the budget must not duplicate the rune gate: %+v", violations)
	}
	// 700 CJK runes = 700 tokens: over the machine floor (600), inside a looser declaration (900).
	wide := entry(strings.Repeat("约", 700))
	quota := index.ExtractSQuotaThresholds("#S quota: C9-8≤900 C7-4≤200 C3-1≤50\n")
	if violations := ValidateEntryWithSQuota(wide, policy, quota); len(violations) != 0 {
		t.Fatalf("a looser Meta quota must raise the floor: %+v", violations)
	}
	if violations := ValidateEntry(wide, policy); len(violations) != 1 || violations[0].Field != "S" || violations[0].Maximum != 600 || violations[0].Actual != 700 {
		t.Fatalf("beyond the machine floor the S limit is the floor itself: %+v", violations)
	}
	policy.S = []FieldBand{{MinC: 1, MaxC: 9, TargetTokens: 1000, MaxTokens: 1000}}
	if violations := ValidateEntry(entry(strings.Repeat("约", 1001)), policy); len(violations) != 1 || violations[0].Maximum != 1000 {
		t.Fatalf("a band above the quota keeps binding: %+v", violations)
	}
	relation := strings.TrimSuffix(strings.Repeat("code:src/r.go,", 60), ",")
	if violations := ValidateEntry("a.go[CG9T]: F:f | R:"+relation+" | A:- | S:-", DefaultPolicy(machinecontract.BudgetModeEnforce)); len(violations) != 1 || violations[0].Field != "R" || violations[0].Maximum != 180 {
		t.Fatalf("R keeps its band: %+v", violations)
	}
	if got := SFieldMaxTokens(FieldBand{MaxTokens: 80}, 7, nil); got != machinecontract.SQuotaMidRunes {
		t.Fatalf("nil quota must floor at the machine default, got %d", got)
	}
}
