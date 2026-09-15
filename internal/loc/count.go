package loc

// classIndex is the number of LineClass values; it sizes the tables
// below. LineClass is a dense enum starting at ClassUnknown == 0.
const classIndex = 4

// deleteTable is the Stats increment for one line that was deleted with
// no counterpart on the new side. Indexed by the line's LineClass.
var deleteTable = [classIndex]Stats{
	ClassUnknown: {Unknown: 1},
	ClassCode:    {DeletedCode: 1},
	ClassComment: {DeletedComment: 1},
	ClassBlank:   {Blank: 1},
}

// insertTable is the Stats increment for one line that was inserted with
// no counterpart on the old side. Indexed by the line's LineClass.
var insertTable = [classIndex]Stats{
	ClassUnknown: {Unknown: 1},
	ClassCode:    {AddedCode: 1},
	ClassComment: {AddedComment: 1},
	ClassBlank:   {Blank: 1},
}

// transitionTable is the class-transition table (plan §1), indexed
// [oldClass][newClass]. It gives the Stats increment for ONE paired line
// inside a change region — an old line replaced by a new one.
//
// The only cell that collapses a pair into a single count is
// code -> code, which is ModifiedCode += 1: a one-line replacement is one
// modified line, not one deleted plus one added. Every other cell is
// exactly deleteTable[old] plus insertTable[new], which is why:
//
//   - code -> comment    = DeletedCode+1,    AddedComment+1
//   - comment -> code    = DeletedComment+1, AddedCode+1
//   - comment -> comment = DeletedComment+1, AddedComment+1 (there is
//     deliberately no ModifiedComment column; see Stats)
//   - code -> blank      = DeletedCode+1,    Blank+1
//   - blank -> code      = Blank+1,          AddedCode+1
//   - blank -> blank     = Blank+2 — both sides count, because Blank is a
//     single bucket for "blank lines added or removed" and a blank line
//     really was removed and another really was added
//   - anything with ClassUnknown on a side contributes Unknown+1 for that
//     side
var transitionTable = [classIndex][classIndex]Stats{
	ClassCode: {
		ClassCode:    {ModifiedCode: 1},
		ClassComment: {DeletedCode: 1, AddedComment: 1},
		ClassBlank:   {DeletedCode: 1, Blank: 1},
		ClassUnknown: {DeletedCode: 1, Unknown: 1},
	},
	ClassComment: {
		ClassCode:    {DeletedComment: 1, AddedCode: 1},
		ClassComment: {DeletedComment: 1, AddedComment: 1},
		ClassBlank:   {DeletedComment: 1, Blank: 1},
		ClassUnknown: {DeletedComment: 1, Unknown: 1},
	},
	ClassBlank: {
		ClassCode:    {Blank: 1, AddedCode: 1},
		ClassComment: {Blank: 1, AddedComment: 1},
		ClassBlank:   {Blank: 2},
		ClassUnknown: {Blank: 1, Unknown: 1},
	},
	ClassUnknown: {
		ClassCode:    {Unknown: 1, AddedCode: 1},
		ClassComment: {Unknown: 1, AddedComment: 1},
		ClassBlank:   {Unknown: 1, Blank: 1},
		ClassUnknown: {Unknown: 2},
	},
}

// Count folds diff hunks plus both sides' line classes into Stats.
//
// hunks must be the tiling Diff returned for oldLines and newLines;
// oldClasses and newClasses are ClassifyLines' output for the same two
// texts. The raw lines are needed as well because an OpEqual hunk only
// says the pair matched after whitespace normalization — Count compares
// the raw texts to tell an untouched line from a whitespace-only change.
//
// The rules, all of them table-driven:
//
//  1. An OpEqual pair whose raw texts are identical contributes nothing;
//     a pair whose raw texts differ contributes Whitespace += 1, once per
//     PAIR.
//  2. A change region is a maximal run of adjacent OpDelete and OpInsert
//     hunks. Its deleted lines D and inserted lines I are paired by
//     position for the first min(len(D), len(I)) of them; the remainder
//     are pure deletes or pure inserts.
//  3. Paired lines go through transitionTable.
//  4. Pure deletes go through deleteTable, pure inserts through
//     insertTable.
//
// Count is defensive about its inputs: a class index outside
// oldClasses/newClasses (a caller that classified a different text than
// it diffed) is read as ClassUnknown, and a line index outside
// oldLines/newLines is read as the empty string. Count never panics and
// never allocates more than the size of one change region.
func Count(hunks []Hunk, oldClasses, newClasses []LineClass, oldLines, newLines []string) Stats {
	var stats Stats

	for i := 0; i < len(hunks); {
		if hunks[i].Op == OpEqual {
			countEqual(&stats, hunks[i], oldLines, newLines)
			i++
			continue
		}

		j := i
		var deleted, inserted []int
		for j < len(hunks) && hunks[j].Op != OpEqual {
			h := hunks[j]
			switch h.Op {
			case OpDelete:
				for x := h.OldStart; x < h.OldEnd; x++ {
					deleted = append(deleted, x)
				}
			case OpInsert:
				for x := h.NewStart; x < h.NewEnd; x++ {
					inserted = append(inserted, x)
				}
			}
			j++
		}
		countRegion(&stats, deleted, inserted, oldClasses, newClasses)
		i = j
	}

	return stats
}

// countEqual applies rule 1 to one OpEqual hunk.
func countEqual(stats *Stats, h Hunk, oldLines, newLines []string) {
	n := min(h.OldEnd-h.OldStart, h.NewEnd-h.NewStart)
	for k := 0; k < n; k++ {
		if lineAt(oldLines, h.OldStart+k) != lineAt(newLines, h.NewStart+k) {
			stats.Whitespace++
		}
	}
}

// countRegion applies rules 2-4 to one change region.
func countRegion(stats *Stats, deleted, inserted []int, oldClasses, newClasses []LineClass) {
	paired := min(len(deleted), len(inserted))
	for k := 0; k < paired; k++ {
		o := classAt(oldClasses, deleted[k])
		n := classAt(newClasses, inserted[k])
		stats.Add(transitionTable[o][n])
	}
	for k := paired; k < len(deleted); k++ {
		stats.Add(deleteTable[classAt(oldClasses, deleted[k])])
	}
	for k := paired; k < len(inserted); k++ {
		stats.Add(insertTable[classAt(newClasses, inserted[k])])
	}
}

// classAt reads classes[i], treating any out-of-range index as
// ClassUnknown rather than panicking.
func classAt(classes []LineClass, i int) LineClass {
	if i < 0 || i >= len(classes) {
		return ClassUnknown
	}
	c := classes[i]
	if c >= classIndex {
		return ClassUnknown
	}
	return c
}

// lineAt reads lines[i], treating any out-of-range index as the empty
// string rather than panicking.
func lineAt(lines []string, i int) string {
	if i < 0 || i >= len(lines) {
		return ""
	}
	return lines[i]
}
