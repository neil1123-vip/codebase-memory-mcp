package main

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

const compactPrefix = "{\"Key\":\"\",\"HelperSHA256\":\"\",\"PayloadSHA256\":\"\""

func compactContextKey(out facts, base string) string {
	return digestJSON(struct {
		Schema                 int
		HelperVersion, Profile string
		Base                   string
	}{out.Schema, out.HelperVersion, "chunk_index_v2", base})
}

type compactSchema struct {
	family int
	slots  uint32
}

type compactCodec struct {
	strings   []string
	stringIDs map[string]int
	schemas   []compactSchema
	schemaIDs map[compactSchema]int
}

// Two typed passes collect only dictionary/schema lookups, then write the wire.
// Neither pass follows local type/symbol references or constructs a legacy JSON body.
type compactEncoder struct {
	codec   *compactCodec
	output  *chunkEncodingBuffer
	err     error
	collect bool
}

func compactWire(entry packageCache, budget *chunkBudgets) ([]byte, error) {
	for _, hash := range []string{entry.Key, entry.HelperSHA256} {
		if len(hash) != sha256.Size*2 || strings.Trim(hash, "0123456789abcdef") != "" {
			return nil, errors.New("invalid compact key or helper hash")
		}
	}
	codec := &compactCodec{stringIDs: make(map[string]int), schemaIDs: make(map[compactSchema]int)}
	encoder := &compactEncoder{codec: codec, collect: true}
	encoder.root(entry)
	if encoder.err != nil {
		return nil, encoder.err
	}
	encoder.collect = false
	encoder.output = &chunkEncodingBuffer{budget: budget}
	encoder.raw(compactPrefix + ",\"Strings\":[")
	for i, text := range codec.strings {
		if i != 0 {
			encoder.raw(",")
		}
		encoder.quoted(text)
	}
	encoder.raw("],\"Schemas\":[")
	for i, schema := range codec.schemas {
		if i != 0 {
			encoder.raw(",")
		}
		encoder.raw("[")
		encoder.integer(int64(schema.family))
		for slot := 0; slot < 32; slot++ {
			if schema.slots&(1<<slot) != 0 {
				encoder.raw(",")
				encoder.integer(int64(slot))
			}
		}
		encoder.raw("]")
	}
	encoder.raw("],\"Root\":")
	encoder.root(entry)
	encoder.raw("}")
	if encoder.err != nil {
		return nil, encoder.err
	}
	data := encoder.output.Bytes()
	if budget.MaxEncodedBytes-budget.EncodedBytes < 192 {
		return nil, errors.New("chunk wire encoding budget exceeded")
	}
	// Reserve before generating the fixed-size expanded header. No newline is made.
	budget.EncodedBytes += 192
	header := "{\"Key\":\"" + entry.Key + "\",\"HelperSHA256\":\"" + entry.HelperSHA256 +
		"\",\"PayloadSHA256\":\"" + digest(data) + "\""
	wire := make([]byte, len(data)+192)
	copy(wire, header)
	copy(wire[len(header):], data[len(compactPrefix):])
	return wire, nil
}

func (e *compactEncoder) raw(text string) {
	if e.collect || e.err != nil {
		return
	}
	count := len(text)
	if remaining := e.output.budget.MaxEncodedBytes - e.output.budget.EncodedBytes; count > remaining {
		count = remaining
	}
	if count < 0 {
		count = 0
	}
	// Slice before converting: even a failed token never allocates an uncharged
	// serialized suffix beyond the remaining work budget.
	_, e.err = e.output.Write([]byte(text[:count]))
	if e.err == nil && count != len(text) {
		e.err = errors.New("chunk wire encoding budget exceeded")
	}
}

func (e *compactEncoder) integer(value int64) {
	if e.collect || e.err != nil {
		return
	}
	length := 1
	if value < 0 {
		length++
	}
	for n := value; n <= -10 || n >= 10; n /= 10 {
		length++
	}
	if length > e.output.budget.MaxEncodedBytes-e.output.budget.EncodedBytes {
		e.err = errors.New("chunk wire encoding budget exceeded")
		return
	}
	var buffer [32]byte
	token := strconv.AppendInt(buffer[:0], value, 10)
	_, e.err = e.output.Write(token)
}

func (e *compactEncoder) number(value int64) {
	if value < 0 {
		e.raw("[-2,")
		e.integer(value)
		e.raw("]")
	} else {
		e.integer(value)
	}
}

func (e *compactEncoder) boolean(value bool) {
	if value {
		e.raw("true")
	} else {
		e.raw("false")
	}
}

func (e *compactEncoder) text(value string) {
	if e.err != nil {
		return
	}
	if e.collect {
		if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			e.err = errors.New("compact string is invalid UTF-8 or contains NUL")
			return
		}
		if _, exists := e.codec.stringIDs[value]; !exists {
			e.codec.stringIDs[value] = len(e.codec.strings)
			e.codec.strings = append(e.codec.strings, value)
		}
		return
	}
	index, exists := e.codec.stringIDs[value]
	if !exists {
		e.err = errors.New("compact traversal string changed")
		return
	}
	e.integer(-int64(index) - 1)
}

// Match encoding/json escaping while producing only bounded tokens, never a full
// temporary escaped string before the budget writer can refuse it.
func (e *compactEncoder) quoted(value string) {
	e.raw("\"")
	start := 0
	for i := 0; i < len(value) && e.err == nil; {
		size, escape := 1, ""
		c := value[i]
		switch c {
		case '"':
			escape = "\\\""
		case '\\':
			escape = "\\\\"
		case '\n':
			escape = "\\n"
		case '\r':
			escape = "\\r"
		case '\t':
			escape = "\\t"
		case '\b':
			escape = "\\b"
		case '\f':
			escape = "\\f"
		default:
			if c < 0x20 || c == '<' || c == '>' || c == '&' {
				escape = "control"
			} else if c >= utf8.RuneSelf {
				r, n := utf8.DecodeRuneInString(value[i:])
				size = n
				if r == '\u2028' {
					escape = "\\u2028"
				} else if r == '\u2029' {
					escape = "\\u2029"
				}
			}
		}
		if escape != "" {
			e.raw(value[start:i])
			if escape == "control" {
				const hex = "0123456789abcdef"
				e.raw("\\u00")
				e.raw(hex[c>>4 : (c>>4)+1])
				e.raw(hex[c&15 : (c&15)+1])
			} else {
				e.raw(escape)
			}
			i += size
			start = i
		} else {
			i += size
			if i-start >= 256 {
				e.raw(value[start:i])
				start = i
			}
		}
	}
	e.raw(value[start:])
	e.raw("\"")
}

func (e *compactEncoder) record(family int, present ...bool) {
	schema := compactSchema{family: family}
	for slot, yes := range present {
		if yes {
			schema.slots |= 1 << slot
		}
	}
	if e.collect {
		if _, exists := e.codec.schemaIDs[schema]; !exists {
			e.codec.schemaIDs[schema] = len(e.codec.schemas)
			e.codec.schemas = append(e.codec.schemas, schema)
		}
		return
	}
	index, exists := e.codec.schemaIDs[schema]
	if !exists {
		e.err = errors.New("compact traversal schema changed")
		return
	}
	e.raw("[")
	e.integer(int64(index))
}

func (e *compactEncoder) field(present bool, write func()) {
	if present && e.err == nil {
		e.raw(",")
		write()
	}
}

func (e *compactEncoder) refs(values []int) {
	e.raw("[-1")
	for _, value := range values {
		e.raw(",")
		e.number(int64(value))
	}
	e.raw("]")
}

func (e *compactEncoder) members(values []memberFact) {
	e.raw("[-1")
	for _, value := range values {
		e.raw(",")
		e.record(3, true, true, value.Package != "", value.Embedded)
		e.field(true, func() { e.text(value.Name) })
		e.field(true, func() { e.number(int64(value.Type)) })
		e.field(value.Package != "", func() { e.text(value.Package) })
		e.field(value.Embedded, func() { e.boolean(value.Embedded) })
		e.raw("]")
	}
	e.raw("]")
}

func (e *compactEncoder) root(entry packageCache) {
	e.record(0, true, true, true, true)
	e.field(true, func() {
		p := entry.Package
		e.record(1, true, true, true, true, p.ForTest != "", true, len(p.Errors) != 0)
		e.field(true, func() { e.text(p.ID) })
		e.field(true, func() { e.text(p.Path) })
		e.field(true, func() { e.text(p.Dir) })
		e.field(true, func() { e.text(p.Name) })
		e.field(p.ForTest != "", func() { e.text(p.ForTest) })
		e.field(true, func() { e.boolean(p.IllTyped) })
		e.field(len(p.Errors) != 0, func() {
			e.raw("[-1")
			for _, text := range p.Errors {
				e.raw(",")
				e.text(text)
			}
			e.raw("]")
		})
		e.raw("]")
	})
	e.field(true, func() {
		if entry.Types == nil {
			e.raw("null")
			return
		}
		e.raw("[-1")
		for _, row := range entry.Types {
			e.raw(",")
			e.typ(row)
		}
		e.raw("]")
	})
	e.field(true, func() {
		if entry.Symbols == nil {
			e.raw("null")
			return
		}
		e.raw("[-1")
		for _, row := range entry.Symbols {
			e.raw(",")
			e.symbol(row)
		}
		e.raw("]")
	})
	e.field(true, func() {
		if entry.Sites == nil {
			e.raw("null")
			return
		}
		e.raw("[-1")
		for _, row := range entry.Sites {
			e.raw(",")
			e.site(row)
		}
		e.raw("]")
	})
	e.raw("]")
}

func (e *compactEncoder) typ(row typeFact) {
	e.record(2, true, true, row.Name != "", row.Package != "", row.OriginSymbol != 0,
		row.Underlying != 0, row.Elem != 0, row.Key != 0, row.Length != 0, row.Direction != 0,
		row.Receiver != 0, row.Variadic, len(row.Params) != 0, len(row.Returns) != 0,
		len(row.TypeParams) != 0, len(row.Args) != 0, len(row.Fields) != 0,
		len(row.Methods) != 0, len(row.Embeds) != 0)
	e.field(true, func() { e.number(int64(row.ID)) })
	e.field(true, func() { e.text(row.Kind) })
	e.field(row.Name != "", func() { e.text(row.Name) })
	e.field(row.Package != "", func() { e.text(row.Package) })
	e.field(row.OriginSymbol != 0, func() { e.number(int64(row.OriginSymbol)) })
	e.field(row.Underlying != 0, func() { e.number(int64(row.Underlying)) })
	e.field(row.Elem != 0, func() { e.number(int64(row.Elem)) })
	e.field(row.Key != 0, func() { e.number(int64(row.Key)) })
	e.field(row.Length != 0, func() { e.number(row.Length) })
	e.field(row.Direction != 0, func() { e.number(int64(row.Direction)) })
	e.field(row.Receiver != 0, func() { e.number(int64(row.Receiver)) })
	e.field(row.Variadic, func() { e.boolean(row.Variadic) })
	e.field(len(row.Params) != 0, func() { e.refs(row.Params) })
	e.field(len(row.Returns) != 0, func() { e.refs(row.Returns) })
	e.field(len(row.TypeParams) != 0, func() { e.refs(row.TypeParams) })
	e.field(len(row.Args) != 0, func() { e.refs(row.Args) })
	e.field(len(row.Fields) != 0, func() { e.members(row.Fields) })
	e.field(len(row.Methods) != 0, func() { e.members(row.Methods) })
	e.field(len(row.Embeds) != 0, func() { e.refs(row.Embeds) })
	e.raw("]")
}

func (e *compactEncoder) symbol(row symbolFact) {
	e.record(4, true, row.PackageID != "", true, true, true, true, true,
		row.Receiver != 0, row.Declaration != nil, true)
	e.field(true, func() { e.number(int64(row.ID)) })
	e.field(row.PackageID != "", func() { e.text(row.PackageID) })
	e.field(true, func() { e.text(row.Package) })
	e.field(true, func() { e.text(row.Kind) })
	e.field(true, func() { e.text(row.Name) })
	e.field(true, func() { e.boolean(row.Internal) })
	e.field(true, func() { e.number(int64(row.Type)) })
	e.field(row.Receiver != 0, func() { e.number(int64(row.Receiver)) })
	e.field(row.Declaration != nil, func() {
		loc := row.Declaration
		e.record(5, true, true, true, true, true, true)
		e.field(true, func() { e.text(loc.Path) })
		e.field(true, func() { e.text(loc.SHA256) })
		e.field(true, func() { e.number(int64(loc.Start)) })
		e.field(true, func() { e.number(int64(loc.End)) })
		e.field(true, func() { e.number(int64(loc.NameStart)) })
		e.field(true, func() { e.number(int64(loc.NameEnd)) })
		e.raw("]")
	})
	e.field(true, func() { e.text(row.LocationStatus) })
	e.raw("]")
}

func (e *compactEncoder) site(row siteFact) {
	e.record(6, true, true, true, true, true, true, true, true, row.Reason != "",
		row.TargetSymbol != 0, row.TargetPackage != "", row.Receiver != 0, row.Type != 0,
		len(row.Args) != 0, len(row.Arguments) != 0, row.HandlerSymbol != 0)
	e.field(true, func() { e.text(row.Path) })
	e.field(true, func() { e.text(row.SHA256) })
	e.field(true, func() { e.text(row.PackageID) })
	e.field(true, func() { e.number(int64(row.Start)) })
	e.field(true, func() { e.number(int64(row.End)) })
	e.field(true, func() { e.number(int64(row.CalleeStart)) })
	e.field(true, func() { e.number(int64(row.CalleeEnd)) })
	e.field(true, func() { e.text(row.Dispatch) })
	e.field(row.Reason != "", func() { e.text(row.Reason) })
	e.field(row.TargetSymbol != 0, func() { e.number(int64(row.TargetSymbol)) })
	e.field(row.TargetPackage != "", func() { e.text(row.TargetPackage) })
	e.field(row.Receiver != 0, func() { e.number(int64(row.Receiver)) })
	e.field(row.Type != 0, func() { e.number(int64(row.Type)) })
	e.field(len(row.Args) != 0, func() { e.refs(row.Args) })
	e.field(len(row.Arguments) != 0, func() { e.refs(row.Arguments) })
	e.field(row.HandlerSymbol != 0, func() { e.number(int64(row.HandlerSymbol)) })
	e.raw("]")
}
