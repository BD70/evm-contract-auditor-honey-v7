// Package cfg ports evm_decon/cfg.py: control flow graph + loop detection.
package cfg

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/evm-auditor/evm-auditor/internal/decon/blocks"
	"github.com/evm-auditor/evm-auditor/internal/decon/stacksim"
)

// LoopInfo mirrors evm_decon.cfg.LoopInfo.
type LoopInfo struct {
	LoopID       int
	HeaderBlock  int
	BackEdgeFrom int
	BodyBlocks   []int
	ExitBlocks   []int
	CounterName  string
	CounterInit  *int64
	CounterBound *int64
	CounterStep  *int64
	Iterations   *int64
	LoopType     string // "for" | "while" | "do-while"
	ParentLoop   *int
	Condition    string
}

// BackEdge mirrors evm_decon.cfg.BackEdge.
type BackEdge struct {
	Source int
	Target int
}

// Analysis mirrors evm_decon.cfg.CFGAnalysis.
type Analysis struct {
	Loops       []LoopInfo
	BackEdges   []BackEdge
	BlockTypes  map[int]string
	BlockLabels map[int]string
	Dominators  map[int]map[int]struct{}
	Reachable   map[int]struct{}
}

// Analyze runs full CFG analysis.
func Analyze(ba blocks.Analysis, sim *stacksim.Result) Analysis {
	if len(ba.Blocks) == 0 {
		return Analysis{
			BlockTypes: map[int]string{}, BlockLabels: map[int]string{},
			Dominators: map[int]map[int]struct{}{}, Reachable: map[int]struct{}{},
		}
	}
	successors := map[int][]int{}
	predecessors := map[int][]int{}
	allIDs := map[int]struct{}{}
	for _, b := range ba.Blocks {
		allIDs[b.ID] = struct{}{}
		successors[b.ID] = append([]int(nil), b.ExitsTo...)
		for _, s := range b.ExitsTo {
			if s < 0 {
				continue
			}
			predecessors[s] = append(predecessors[s], b.ID)
		}
	}
	for id := range allIDs {
		if _, ok := successors[id]; !ok {
			successors[id] = nil
		}
		if _, ok := predecessors[id]; !ok {
			predecessors[id] = nil
		}
	}

	reachable := computeReachable(0, successors, allIDs)
	doms := computeDominators(0, successors, predecessors, reachable)
	backEdges := findBackEdges(successors, doms, reachable)
	loops := computeLoops(backEdges, successors, predecessors, sim)
	detectNesting(loops)
	types := classifyBlocks(ba.Blocks, loops, backEdges, sim)
	labels := labelBlocks(ba.Blocks, types, loops, sim)

	return Analysis{
		Loops: loops, BackEdges: backEdges, BlockTypes: types, BlockLabels: labels,
		Dominators: doms, Reachable: reachable,
	}
}

func computeReachable(entry int, succ map[int][]int, allIDs map[int]struct{}) map[int]struct{} {
	visited := map[int]struct{}{}
	queue := []int{entry}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if _, seen := visited[node]; seen {
			continue
		}
		if _, ok := allIDs[node]; !ok {
			continue
		}
		visited[node] = struct{}{}
		for _, s := range succ[node] {
			if s < 0 {
				continue
			}
			if _, seen := visited[s]; !seen {
				queue = append(queue, s)
			}
		}
	}
	return visited
}

func computeDominators(entry int, succ, pred map[int][]int, reachable map[int]struct{}) map[int]map[int]struct{} {
	doms := map[int]map[int]struct{}{}
	for n := range reachable {
		if n == entry {
			doms[n] = map[int]struct{}{entry: {}}
		} else {
			doms[n] = copySet(reachable)
		}
	}
	changed := true
	iter := 0
	for changed && iter < 100 {
		changed = false
		iter++
		for n := range reachable {
			if n == entry {
				continue
			}
			preds := []int{}
			for _, p := range pred[n] {
				if _, ok := reachable[p]; ok {
					preds = append(preds, p)
				}
			}
			if len(preds) == 0 {
				continue
			}
			newDom := copySet(reachable)
			for _, p := range preds {
				newDom = intersect(newDom, doms[p])
			}
			newDom[n] = struct{}{}
			if !setsEqual(newDom, doms[n]) {
				doms[n] = newDom
				changed = true
			}
		}
	}
	return doms
}

func findBackEdges(succ map[int][]int, doms map[int]map[int]struct{}, reachable map[int]struct{}) []BackEdge {
	out := []BackEdge{}
	keys := sortedKeys(reachable)
	for _, a := range keys {
		for _, b := range succ[a] {
			if b < 0 {
				continue
			}
			if _, ok := doms[a][b]; ok {
				out = append(out, BackEdge{Source: a, Target: b})
			}
		}
	}
	return out
}

func computeLoops(backEdges []BackEdge, succ, pred map[int][]int, sim *stacksim.Result) []LoopInfo {
	loops := []LoopInfo{}
	for idx, be := range backEdges {
		header := be.Target
		tail := be.Source
		body := naturalLoopBody(header, tail, pred)
		exitBlocks := []int{}
		seenExit := map[int]struct{}{}
		bodySorted := sortedKeys(body)
		for _, b := range bodySorted {
			for _, s := range succ[b] {
				if s < 0 {
					continue
				}
				if _, inBody := body[s]; inBody {
					continue
				}
				if _, seen := seenExit[s]; seen {
					continue
				}
				seenExit[s] = struct{}{}
				exitBlocks = append(exitBlocks, s)
			}
		}
		var counterInit, counterBound, counterStep, iterations *int64
		loopType := "while"
		condition := ""
		var trace *stacksim.BlockTrace
		if sim != nil {
			trace = sim.Traces[header]
		}
		if trace != nil && trace.BranchCondition != nil {
			cond := trace.BranchCondition
			condition = cond.String()
			counterBound = extractBound(trace)
		}
		headerPreds := []int{}
		for _, p := range pred[header] {
			if _, inBody := body[p]; !inBody {
				headerPreds = append(headerPreds, p)
			}
		}
		for _, pid := range headerPreds {
			if sim == nil {
				continue
			}
			pt := sim.Traces[pid]
			if pt == nil {
				continue
			}
			for i := len(pt.ExitStack) - 1; i >= 0; i-- {
				sv := pt.ExitStack[i]
				if !sv.IsConst() || sv.Const == nil {
					continue
				}
				if sv.Const.Cmp(big1000) >= 0 {
					continue
				}
				v := sv.Const.Int64()
				counterInit = &v
				break
			}
			if counterInit != nil {
				break
			}
		}
		if sim != nil {
			tt := sim.Traces[tail]
			if tt != nil {
				for _, op := range tt.Operations {
					if strings.Contains(op.Description, "+") || strings.Contains(op.Description, "- ") {
						if step, ok := extractStep(op.Description); ok {
							counterStep = &step
						}
					}
				}
			}
			if counterStep == nil {
				for _, bid := range bodySorted {
					bt := sim.Traces[bid]
					if bt == nil {
						continue
					}
					for _, ann := range bt.StackAnnotations {
						if strings.Contains(ann, "+ 0x01") || strings.Contains(ann, "+ 1") {
							v := int64(1)
							counterStep = &v
							break
						}
					}
					if counterStep != nil {
						break
					}
				}
			}
		}
		if counterBound != nil && counterInit != nil && counterStep != nil && *counterStep != 0 {
			iter := (*counterBound - *counterInit) / *counterStep
			if iter > 0 {
				loopType = "for"
			}
			iterations = &iter
		}
		loops = append(loops, LoopInfo{
			LoopID:       idx,
			HeaderBlock:  header,
			BackEdgeFrom: tail,
			BodyBlocks:   bodySorted,
			ExitBlocks:   exitBlocks,
			CounterName:  fmt.Sprintf("var_%d", idx),
			CounterInit:  counterInit,
			CounterBound: counterBound,
			CounterStep:  counterStep,
			Iterations:   iterations,
			LoopType:     loopType,
			Condition:    condition,
		})
	}
	return loops
}

func naturalLoopBody(header, tail int, pred map[int][]int) map[int]struct{} {
	body := map[int]struct{}{header: {}, tail: {}}
	if header == tail {
		return body
	}
	worklist := []int{tail}
	for len(worklist) > 0 {
		node := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		for _, p := range pred[node] {
			if _, in := body[p]; !in {
				body[p] = struct{}{}
				worklist = append(worklist, p)
			}
		}
	}
	return body
}

func detectNesting(loops []LoopInfo) {
	for i := range loops {
		for j := range loops {
			if i == j {
				continue
			}
			outerBody := map[int]struct{}{}
			for _, b := range loops[j].BodyBlocks {
				outerBody[b] = struct{}{}
			}
			if _, in := outerBody[loops[i].HeaderBlock]; in {
				p := loops[j].LoopID
				loops[i].ParentLoop = &p
			}
		}
	}
}

func classifyBlocks(bs []blocks.BasicBlock, loops []LoopInfo, backEdges []BackEdge, sim *stacksim.Result) map[int]string {
	types := map[int]string{}
	loopHeaders := map[int]struct{}{}
	loopBodies := map[int]struct{}{}
	loopExits := map[int]struct{}{}
	backEdgeSrc := map[int]struct{}{}
	for _, l := range loops {
		loopHeaders[l.HeaderBlock] = struct{}{}
		for _, b := range l.BodyBlocks {
			loopBodies[b] = struct{}{}
		}
		for _, e := range l.ExitBlocks {
			loopExits[e] = struct{}{}
		}
	}
	for _, be := range backEdges {
		backEdgeSrc[be.Source] = struct{}{}
	}
	for _, b := range bs {
		bid := b.ID
		var tr *stacksim.BlockTrace
		if sim != nil {
			tr = sim.Traces[bid]
		}
		switch {
		case bid == 0:
			types[bid] = "entry"
		case isIn(loopHeaders, bid):
			types[bid] = "loop_header"
		case isIn(backEdgeSrc, bid) && isIn(loopBodies, bid):
			if tr != nil && anyOpContains(tr.Operations, "+") {
				types[bid] = "loop_increment"
			} else {
				types[bid] = "loop_tail"
			}
		case isIn(loopBodies, bid):
			if tr != nil && len(tr.Operations) > 0 {
				hasMul := anyOpContains(tr.Operations, "*")
				hasMem := anyOpCategory(tr.Operations, "memory")
				hasStor := anyOpCategory(tr.Operations, "storage")
				hasCall := anyOpCategory(tr.Operations, "call")
				switch {
				case hasCall:
					types[bid] = "loop_body_call"
				case hasStor:
					types[bid] = "loop_body_storage"
				case hasMul || hasMem:
					types[bid] = "loop_body"
				default:
					types[bid] = "loop_setup"
				}
			} else {
				types[bid] = "loop_setup"
			}
		default:
			switch b.Terminator {
			case "RETURN":
				types[bid] = "return"
			case "REVERT":
				types[bid] = "revert"
			case "STOP":
				types[bid] = "halt"
			case "JUMPI":
				types[bid] = "conditional"
			default:
				types[bid] = "basic"
			}
		}
	}
	return types
}

func labelBlocks(bs []blocks.BasicBlock, types map[int]string, loops []LoopInfo, sim *stacksim.Result) map[int]string {
	labels := map[int]string{}
	headerToLoop := map[int]LoopInfo{}
	for _, l := range loops {
		headerToLoop[l.HeaderBlock] = l
	}
	for _, b := range bs {
		bid := b.ID
		btype := types[bid]
		var tr *stacksim.BlockTrace
		if sim != nil {
			tr = sim.Traces[bid]
		}
		switch btype {
		case "entry":
			labels[bid] = "Initialize"
		case "loop_header":
			loop, ok := headerToLoop[bid]
			if ok && loop.Condition != "" {
				labels[bid] = "Loop check: " + loop.Condition
			} else {
				labels[bid] = "Loop header"
			}
		case "loop_body":
			if tr != nil && len(tr.Operations) > 0 {
				ops := []string{}
				for i := 0; i < len(tr.Operations) && i < 3; i++ {
					ops = append(ops, tr.Operations[i].Description)
				}
				labels[bid] = "Loop body: " + strings.Join(ops, ", ")
			} else {
				labels[bid] = "Loop body"
			}
		case "loop_setup":
			labels[bid] = "Loop setup"
		case "loop_increment":
			labels[bid] = "Loop increment"
		case "loop_tail":
			labels[bid] = "Back to loop header"
		case "return":
			if tr != nil && len(tr.Operations) > 0 {
				labels[bid] = tr.Operations[len(tr.Operations)-1].Description
			} else {
				labels[bid] = "Return"
			}
		case "revert":
			labels[bid] = "Revert"
		case "conditional":
			if tr != nil && tr.BranchCondition != nil {
				labels[bid] = "Conditional: " + tr.BranchCondition.String()
			} else {
				labels[bid] = "Conditional branch"
			}
		default:
			labels[bid] = "Basic block"
		}
	}
	return labels
}

var stepRegex = regexp.MustCompile(`\+\s*(\d+|0x[0-9a-fA-F]+)`)

func extractStep(desc string) (int64, bool) {
	m := stepRegex.FindStringSubmatch(desc)
	if m == nil {
		return 0, false
	}
	val := m[1]
	if strings.HasPrefix(val, "0x") {
		v, err := strconv.ParseInt(val[2:], 16, 64)
		if err == nil {
			return v, true
		}
	}
	v, err := strconv.ParseInt(val, 10, 64)
	if err == nil {
		return v, true
	}
	return 0, false
}

func extractBound(trace *stacksim.BlockTrace) *int64 {
	for _, ann := range trace.StackAnnotations {
		if !strings.Contains(ann, "<") && !strings.Contains(ann, ">") {
			continue
		}
		cleaned := strings.NewReplacer("(", "", ")", "").Replace(ann)
		for _, p := range strings.Fields(cleaned) {
			if strings.HasPrefix(p, "0x") {
				if v, err := strconv.ParseInt(p[2:], 16, 64); err == nil {
					if v > 0 && v < 10000 {
						return &v
					}
				}
				continue
			}
			if v, err := strconv.ParseInt(p, 10, 64); err == nil {
				if v > 0 && v < 10000 {
					return &v
				}
			}
		}
	}
	return nil
}

func anyOpContains(ops []stacksim.OperationRecord, sub string) bool {
	for _, op := range ops {
		if strings.Contains(op.Description, sub) {
			return true
		}
	}
	return false
}

func anyOpCategory(ops []stacksim.OperationRecord, cat string) bool {
	for _, op := range ops {
		if op.Category == cat {
			return true
		}
	}
	return false
}

func isIn(m map[int]struct{}, k int) bool { _, ok := m[k]; return ok }

func copySet(s map[int]struct{}) map[int]struct{} {
	out := make(map[int]struct{}, len(s))
	for k := range s {
		out[k] = struct{}{}
	}
	return out
}

func intersect(a, b map[int]struct{}) map[int]struct{} {
	out := map[int]struct{}{}
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if _, ok := b[k]; ok {
			out[k] = struct{}{}
		}
	}
	return out
}

func setsEqual(a, b map[int]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func sortedKeys(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

var big1000 = big.NewInt(1000)
