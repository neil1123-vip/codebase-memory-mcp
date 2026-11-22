// Command go-package-facts exports a bounded, manifest-scoped Go compiler snapshot.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	helperVersion   = "go-package-facts-2"
	indexVersion    = "go-package-facts-3"
	chunkVersion    = "go-package-facts-4"
	compactVersion  = "go-package-facts-5"
	maxSourceFiles  = 50000
	maxPackageFiles = 200000
	maxSourceBytes  = 256 << 20
	maxJSONBytes    = 32 << 20
	maxCallSites    = 100000
	maxBudgetMS     = 300000
	maxTypes        = 50000
	maxSymbols      = 50000
)

type fileFact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type location struct {
	fileFact
	Start     int `json:"start"`
	End       int `json:"end"`
	NameStart int `json:"name_start"`
	NameEnd   int `json:"name_end"`
}

type contextFact struct {
	ToolVersion        string            `json:"tool_version"`
	ToolSHA256         string            `json:"tool_sha256"`
	HelperSHA256       string            `json:"helper_sha256"`
	Env                map[string]string `json:"env"`
	Patterns           []string          `json:"patterns"`
	BuildFlags         []string          `json:"build_flags"`
	CGOPolicy          string            `json:"cgo_policy"`
	ManifestSHA256     string            `json:"manifest_sha256"`
	ConfigSHA256       string            `json:"config_sha256"`
	SourceSHA256       string            `json:"source_sha256"`
	ExportsSHA256      string            `json:"exports_sha256"`
	DependenciesSHA256 string            `json:"dependencies_sha256"`
}

type cacheFact struct {
	Key          string              `json:"key"`
	Hit          bool                `json:"hit"`
	PackageKeys  map[string]string   `json:"package_keys,omitempty"`
	PackageFiles map[string][]string `json:"package_files,omitempty"`
	Reused       []string            `json:"reused_packages,omitempty"`
	Rebuilt      []string            `json:"rebuilt_packages,omitempty"`
	Checked      []string            `json:"checked_packages,omitempty"`
}

type packageFact struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Dir      string   `json:"dir"`
	Name     string   `json:"name"`
	ForTest  string   `json:"for_test,omitempty"`
	IllTyped bool     `json:"ill_typed"`
	Errors   []string `json:"errors,omitempty"`
}

type memberFact struct {
	Name     string `json:"name"`
	Type     int    `json:"type"`
	Package  string `json:"package,omitempty"`
	Embedded bool   `json:"embedded,omitempty"`
}

type typeFact struct {
	ID           int          `json:"id"`
	Kind         string       `json:"kind"`
	Name         string       `json:"name,omitempty"`
	Package      string       `json:"package,omitempty"`
	OriginSymbol int          `json:"origin_symbol,omitempty"`
	Underlying   int          `json:"underlying,omitempty"`
	Elem         int          `json:"elem,omitempty"`
	Key          int          `json:"key,omitempty"`
	Length       int64        `json:"length,omitempty"`
	Direction    int          `json:"direction,omitempty"`
	Receiver     int          `json:"receiver,omitempty"`
	Variadic     bool         `json:"variadic,omitempty"`
	Params       []int        `json:"params,omitempty"`
	Returns      []int        `json:"returns,omitempty"`
	TypeParams   []int        `json:"type_params,omitempty"`
	Args         []int        `json:"args,omitempty"`
	Fields       []memberFact `json:"fields,omitempty"`
	Methods      []memberFact `json:"methods,omitempty"`
	Embeds       []int        `json:"embeds,omitempty"`
}

type symbolFact struct {
	ID             int       `json:"id"`
	PackageID      string    `json:"package_id,omitempty"`
	Package        string    `json:"package"`
	Kind           string    `json:"kind"`
	Name           string    `json:"name"`
	Internal       bool      `json:"internal"`
	Type           int       `json:"type"`
	Receiver       int       `json:"receiver,omitempty"`
	Declaration    *location `json:"declaration,omitempty"`
	LocationStatus string    `json:"location_status"`
}

type siteFact struct {
	fileFact
	PackageID     string `json:"package_id"`
	Start         int    `json:"start"`
	End           int    `json:"end"`
	CalleeStart   int    `json:"callee_start"`
	CalleeEnd     int    `json:"callee_end"`
	Dispatch      string `json:"dispatch"`
	Reason        string `json:"reason,omitempty"`
	TargetSymbol  int    `json:"target_symbol,omitempty"`
	TargetPackage string `json:"target_package,omitempty"`
	Receiver      int    `json:"receiver,omitempty"`
	Type          int    `json:"type,omitempty"`
	Args          []int  `json:"args,omitempty"`
	Arguments     []int  `json:"arguments,omitempty"`
	HandlerSymbol int    `json:"handler_symbol,omitempty"`
}

type facts struct {
	Schema        int           `json:"schema"`
	Language      string        `json:"language"`
	HelperVersion string        `json:"helper_version"`
	Status        string        `json:"status"`
	Complete      bool          `json:"complete"`
	Root          string        `json:"root"`
	Context       contextFact   `json:"context"`
	Cache         cacheFact     `json:"cache"`
	Files         []fileFact    `json:"files,omitempty"`
	Packages      []packageFact `json:"packages,omitempty"`
	Types         []typeFact    `json:"types,omitempty"`
	Symbols       []symbolFact  `json:"symbols,omitempty"`
	Sites         []siteFact    `json:"sites,omitempty"`
	Errors        []string      `json:"errors,omitempty"`
	Index         *packageIndex `json:"-"`
}

type indexFile struct {
	fileFact
	ByteLength        int      `json:"byte_length"`
	Selection         string   `json:"selection"`
	SelectionVerified bool     `json:"selection_verified,omitempty"`
	PackageIDs        []string `json:"package_ids"`
	Reason            string   `json:"reason,omitempty"`
}

type fragmentDescriptor struct {
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	ByteLength int    `json:"byte_length"`
	Types      int    `json:"types"`
	Symbols    int    `json:"symbols"`
	Sites      int    `json:"sites"`
}

type indexPackage struct {
	packageFact
	ForTest  string              `json:"for_test"`
	Status   string              `json:"status"`
	Key      string              `json:"key"`
	Files    []string            `json:"files"`
	Fragment *fragmentDescriptor `json:"fragment"`
	Reason   string              `json:"reason,omitempty"`
}

type packageIndex struct {
	InventoryComplete   bool
	InputSnapshotStable bool
	Files               []indexFile
	Packages            []indexPackage
	Summary             map[string]int
	Chunks              []chunkFact
	Budgets             *chunkBudgets
}

type chunkFragment struct {
	PackageID     string `json:"package_id"`
	Key           string `json:"key"`
	File          string `json:"file"`
	SHA256        string `json:"sha256"`
	ByteLength    int    `json:"byte_length"`
	RawSHA256     string `json:"raw_sha256"`
	RawByteLength int    `json:"raw_byte_length"`
	Types         int    `json:"types"`
	Symbols       int    `json:"symbols"`
	Sites         int    `json:"sites"`
}

type chunkFact struct {
	Key        string          `json:"key"`
	Files      []string        `json:"files"`
	PackageIDs []string        `json:"package_ids"`
	Status     string          `json:"status"`
	Reason     string          `json:"reason,omitempty"`
	Fragments  []chunkFragment `json:"fragments"`
}

type chunkBudgets struct {
	MaxChunkRawBytes             int `json:"max_chunk_raw_bytes"`
	MaxChunkSites                int `json:"max_chunk_sites"`
	MaxReferencedCompressedBytes int `json:"max_referenced_compressed_bytes"`
	MaxExpandedBytes             int `json:"max_expanded_bytes"`
	MaxEncodedBytes              int `json:"max_encoded_bytes"`
	MaxExportAttempts            int `json:"max_export_attempts"`
	ReferencedCompressedBytes    int `json:"referenced_compressed_bytes"`
	ExpandedBytes                int `json:"expanded_bytes"`
	EncodedBytes                 int `json:"encoded_bytes"`
	ExportAttempts               int `json:"export_attempts"`
}

type chunkIndexPackage struct {
	indexPackage
	Fragment *fragmentDescriptor `json:"fragment,omitempty"`
}

func (out facts) MarshalJSON() ([]byte, error) {
	type plainFacts facts
	if out.Index == nil {
		return json.Marshal(plainFacts(out))
	}
	if out.Schema == 3 || out.Schema == 4 {
		profile := "chunk_index_v1"
		if out.Schema == 4 {
			profile = "chunk_index_v2"
		}
		packages := make([]chunkIndexPackage, len(out.Index.Packages))
		for i, row := range out.Index.Packages {
			packages[i].indexPackage = row
		}
		return json.Marshal(struct {
			plainFacts
			Kind                string              `json:"kind"`
			Profile             string              `json:"profile"`
			InventoryComplete   bool                `json:"inventory_complete"`
			InputSnapshotStable bool                `json:"input_snapshot_stable"`
			Files               []indexFile         `json:"files"`
			Packages            []chunkIndexPackage `json:"packages"`
			Chunks              []chunkFact         `json:"chunks"`
			Budgets             *chunkBudgets       `json:"budgets"`
			Summary             map[string]int      `json:"summary,omitempty"`
		}{plainFacts(out), "go_chunk_index", profile, out.Index.InventoryComplete,
			out.Index.InputSnapshotStable, out.Index.Files, packages,
			out.Index.Chunks, out.Index.Budgets, out.Index.Summary})
	}
	return json.Marshal(struct {
		plainFacts
		Kind                string         `json:"kind"`
		InventoryComplete   bool           `json:"inventory_complete"`
		InputSnapshotStable bool           `json:"input_snapshot_stable"`
		Files               []indexFile    `json:"files"`
		Packages            []indexPackage `json:"packages"`
		Summary             map[string]int `json:"summary,omitempty"`
	}{plainFacts(out), "go_package_index", out.Index.InventoryComplete,
		out.Index.InputSnapshotStable, out.Index.Files, out.Index.Packages, out.Index.Summary})
}

type options struct {
	Root, Manifest, Cache, Go string
	Patterns                  []string
	BudgetMS, MaxSites        int
	MaxBytes                  int
	PackageIndex              bool
	ChunkIndex                bool
	ChunkIndexV2              bool
	Cgo                       bool
}

func initialFacts(opts options) facts {
	out := facts{Schema: 1, Language: "go", HelperVersion: helperVersion, Status: "degraded"}
	if opts.PackageIndex {
		out.Schema, out.HelperVersion, out.Status = 2, indexVersion, "partial"
		out.Index = &packageIndex{Files: []indexFile{}, Packages: []indexPackage{}}
	}
	if opts.ChunkIndex || opts.ChunkIndexV2 {
		out.Schema, out.HelperVersion, out.Status = 3, chunkVersion, "partial"
		if opts.ChunkIndexV2 {
			out.Schema, out.HelperVersion = 4, compactVersion
		}
		out.Index = &packageIndex{Files: []indexFile{}, Packages: []indexPackage{},
			Chunks: []chunkFact{}, Budgets: &chunkBudgets{
				MaxChunkRawBytes: opts.MaxBytes, MaxChunkSites: opts.MaxSites,
				MaxReferencedCompressedBytes: opts.MaxBytes, MaxExpandedBytes: maxSourceBytes,
				MaxEncodedBytes: 2 * maxSourceBytes,
			}}
	}
	return out
}

type module struct {
	Dir, GoMod, GoVersion string
	Replace               *module
}

type listPackage struct {
	ImportPath, Name, Dir, ForTest, Export   string
	Standard                                 bool
	GoFiles, CompiledGoFiles, Imports        []string
	CgoFiles, HFiles, MFiles, InvalidGoFiles []string
	ImportMap                                map[string]string
	Module                                   *module
	Error                                    *struct{ Err string }
	DepsErrors                               []struct{ Err string }
}

type sourceFile struct {
	Abs, Path, SHA256 string
	Data              []byte
}

type checkedPackage struct {
	Meta            *listPackage
	Types           *types.Package
	Info            *types.Info
	Files           []*ast.File
	Fact            packageFact
	CgoDeclarations map[string]cgoTarget
}

type loader struct {
	ctx           context.Context
	root          string
	fset          *token.FileSet
	listed        map[string]*listPackage
	checked       map[string]*checkedPackage
	loading       map[string]bool
	sources       map[string]*sourceFile
	manifest      map[string]*sourceFile
	locations     map[types.Object]*location
	pkgIDs        map[*types.Package]string
	identities    map[string]string
	exportDeps    map[string]bool
	gc            types.Importer
	goarch        string
	sourceBytes   int
	sourceCount   int
	strictImports bool
	cgoHeaders    bool
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func digestJSON(value any) string {
	data, _ := json.Marshal(value)
	return digest(data)
}

func canonical(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func excludedTree(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.HasPrefix(strings.ToLower(part), ".tmp-rebase-") {
			return true
		}
	}
	return false
}

func within(root, path string) (string, bool) {
	if excludedTree(root) || excludedTree(path) {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(rel) {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	return rel, true
}

func readSource(root, path string) (*sourceFile, error) {
	abs, err := canonical(path)
	if err != nil {
		return nil, err
	}
	data, err := readLimited(abs, 8<<20)
	if err != nil {
		return nil, err
	}
	name := filepath.ToSlash(abs)
	if rel, ok := within(root, abs); ok {
		name = rel
	}
	return &sourceFile{Abs: abs, Path: name, SHA256: digest(data), Data: data}, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("input byte budget exceeded: %s", path)
	}
	return data, err
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func cgoNativeSource(path string) bool {
	return strings.HasSuffix(path, ".h") || (runtime.GOOS == "darwin" && strings.HasSuffix(path, ".m"))
}

func readManifest(ctx context.Context, root, path string, cgoHeaders bool) (map[string]*sourceFile, []fileFact, error) {
	if path == "" {
		return nil, nil, errors.New("discovery manifest is required; no files were admitted")
	}
	data, err := readLimited(path, 16<<20)
	if err != nil {
		return nil, nil, err
	}
	var manifest struct {
		Files []fileFact `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("manifest: %w", err)
	}
	if len(manifest.Files) > maxSourceFiles {
		return nil, nil, errors.New("manifest file budget exceeded")
	}
	paths := make(map[string]fileFact)
	var files []fileFact
	for _, entry := range manifest.Files {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path)))
		if filepath.IsAbs(entry.Path) || clean != entry.Path || clean == "." {
			return nil, nil, fmt.Errorf("noncanonical manifest path %q", entry.Path)
		}
		abs := filepath.Join(root, filepath.FromSlash(clean))
		rel, ok := within(root, abs)
		if !ok || rel != clean {
			return nil, nil, fmt.Errorf("manifest path is outside the admitted root: %q", clean)
		}
		if !strings.HasSuffix(clean, ".go") && !(cgoHeaders && cgoNativeSource(clean)) {
			continue
		}
		if _, exists := paths[abs]; exists {
			return nil, nil, fmt.Errorf("duplicate manifest file %s", clean)
		}
		paths[abs] = entry
		files = append(files, entry)
	}
	if len(files) == 0 {
		return nil, nil, errors.New("manifest admits no Go files")
	}
	admitted := make(map[string]*sourceFile, len(files))
	sourceBytes := 0
	var mu sync.Mutex
	err = checkPaths(ctx, paths, func(abs string, entry fileFact) error {
		source, err := readSource(root, abs)
		if err != nil {
			return err
		}
		if source.Path != entry.Path {
			return fmt.Errorf("manifest path aliases another file: %q", entry.Path)
		}
		if source.SHA256 != entry.SHA256 {
			return fmt.Errorf("manifest SHA-256 mismatch for %s", entry.Path)
		}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := admitted[source.Abs]; exists {
			return fmt.Errorf("duplicate manifest file %s", entry.Path)
		}
		if len(source.Data) > maxSourceBytes-sourceBytes {
			return errors.New("source byte budget exceeded")
		}
		admitted[source.Abs] = source
		sourceBytes += len(source.Data)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return admitted, files, nil
}

func safeEnv(cgo bool) []string {
	var env []string
	for _, entry := range os.Environ() {
		key := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
		if key != "GOTOOLCHAIN" && key != "GOPROXY" && key != "GOSUMDB" &&
			key != "GONOPROXY" && key != "GOVCS" && key != "GOCACHEPROG" &&
			key != "CGO_ENABLED" && key != "GOAUTH" {
			env = append(env, entry)
		}
	}
	enabled := "0"
	if cgo {
		enabled = "1"
	}
	return append(env, "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GONOPROXY=none",
		"GOVCS=*:off", "GOCACHEPROG=", "CGO_ENABLED="+enabled, "GOAUTH=off")
}

func buildFlags(env map[string]string) ([]string, error) {
	var flags []string
	mod := ""
	modfile := false
	for _, flag := range strings.Fields(env["GOFLAGS"]) {
		if strings.ContainsAny(flag, "'\"") {
			return nil, fmt.Errorf("quoted GOFLAGS are outside this pilot's read-only build context: %s", flag)
		}
		switch {
		case strings.HasPrefix(flag, "-tags="):
		case flag == "-mod=vendor" || flag == "-mod=readonly":
			mod = strings.TrimPrefix(flag, "-mod=")
		case strings.HasPrefix(flag, "-modfile="):
			path := strings.TrimPrefix(flag, "-modfile=")
			if modfile || !filepath.IsAbs(path) || !strings.HasSuffix(path, ".mod") {
				return nil, fmt.Errorf("GOFLAGS requires a single absolute .mod file: %s", flag)
			}
			modfile = true
		case flag == "-trimpath" || flag == "-buildvcs=false" || flag == "-buildvcs=auto" ||
			flag == "-buildvcs=true":
		case strings.HasPrefix(flag, "-p="):
			if n, err := strconv.Atoi(strings.TrimPrefix(flag, "-p=")); err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid GOFLAGS build parallelism: %s", flag)
			}
		default:
			return nil, fmt.Errorf("GOFLAGS flag is not allowed in read-only compiler facts: %s", flag)
		}
		flags = append(flags, flag)
	}
	if mod == "" {
		vendor := false
		for _, path := range []string{env["GOMOD"], env["GOWORK"]} {
			if path != "" && path != "off" && path != os.DevNull {
				_, err := os.Stat(filepath.Join(filepath.Dir(path), "vendor", "modules.txt"))
				vendor = vendor || err == nil
			}
		}
		if vendor {
			flags = append(flags, "-mod=vendor")
		} else {
			flags = append(flags, "-mod=readonly")
		}
	}
	return flags, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("Go tool output budget exceeded")
	}
	return b.Buffer.Write(p)
}

func runGo(ctx context.Context, root string, opts options, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, opts.Go, args...)
	cmd.Dir, cmd.Env, cmd.WaitDelay = root, safeEnv(opts.Cgo), 2*time.Second
	out := &limitedBuffer{limit: 32 << 20}
	stderr := &limitedBuffer{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out.Bytes(), nil
}

func packagePath(id string) string {
	return strings.SplitN(id, " [", 2)[0]
}

func (l *loader) canonicalInput(path string) (string, error) {
	// Reuse direct paths from this snapshot. The boundary checks still resolve
	// each path afresh, and alias lookups still check for retargeting on use.
	if previous, ok := l.identities[path]; ok && previous == path {
		return previous, nil
	}
	abs, err := canonical(path)
	if err != nil {
		return "", err
	}
	if previous, ok := l.identities[path]; ok && previous != abs {
		return "", fmt.Errorf("compiler input identity changed during analysis: %s", path)
	}
	if l.identities != nil {
		l.identities[path] = abs
	}
	return abs, nil
}

func (l *loader) source(path, dir string) (*sourceFile, error) {
	if err := l.ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	abs, err := l.canonicalInput(path)
	if err != nil {
		return nil, err
	}
	if source := l.sources[abs]; source != nil {
		return source, nil
	}
	source := l.manifest[abs]
	if source == nil {
		if l.sourceCount >= maxSourceFiles {
			return nil, errors.New("source file budget exceeded")
		}
		source, err = readSource(l.root, abs)
		if err != nil {
			return nil, err
		}
		if len(source.Data) > maxSourceBytes-l.sourceBytes {
			return nil, errors.New("source byte budget exceeded")
		}
		l.sourceBytes += len(source.Data)
		l.sourceCount++
	}
	l.sources[abs] = source
	return source, nil
}

type packageImporter struct {
	loader *loader
	meta   *listPackage
}

func (i packageImporter) Import(path string) (*types.Package, error) {
	id := path
	if mapped := i.meta.ImportMap[path]; mapped != "" {
		id = mapped
	}
	if meta := i.loader.listed[id]; meta != nil && !i.loader.exportDeps[id] {
		dir, err := i.loader.canonicalInput(meta.Dir)
		if err == nil {
			if _, own := within(i.loader.root, dir); own {
				pkg := i.loader.check(id)
				if pkg.Types != nil && !i.loader.loading[id] &&
					(!i.loader.strictImports || !pkg.Fact.IllTyped) {
					return pkg.Types, nil
				}
				return nil, fmt.Errorf("package %s could not be checked", id)
			}
		}
	}
	return i.loader.gc.Import(path)
}

func addError(fact *packageFact, message string) {
	fact.IllTyped = true
	if len(fact.Errors) < 32 {
		fact.Errors = append(fact.Errors, message)
	}
}

func (l *loader) check(id string) *checkedPackage {
	if pkg := l.checked[id]; pkg != nil {
		return pkg
	}
	meta := l.listed[id]
	pkg := &checkedPackage{Meta: meta, Info: &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances: make(map[*ast.Ident]types.Instance),
	}, Fact: packageFact{ID: id, Path: packagePath(id), Dir: filepath.ToSlash(meta.Dir),
		Name: meta.Name, ForTest: meta.ForTest}}
	l.checked[id], l.loading[id] = pkg, true
	defer delete(l.loading, id)
	if meta.Error != nil {
		addError(&pkg.Fact, meta.Error.Err)
	}
	for _, err := range meta.DepsErrors {
		addError(&pkg.Fact, err.Err)
	}
	files := append([]string(nil), meta.CompiledGoFiles...)
	if len(files) == 0 {
		files = append(files, meta.GoFiles...)
	}
	sort.Strings(files)
	for _, path := range files {
		if l.ctx.Err() != nil {
			addError(&pkg.Fact, l.ctx.Err().Error())
			break
		}
		source, err := l.source(path, meta.Dir)
		if err != nil {
			addError(&pkg.Fact, err.Error())
			continue
		}
		file, err := parser.ParseFile(l.fset, source.Abs, source.Data, parser.AllErrors)
		if err != nil {
			addError(&pkg.Fact, err.Error())
		}
		if file != nil {
			pkg.Files = append(pkg.Files, file)
		}
	}
	config := types.Config{Importer: packageImporter{l, meta},
		Sizes: types.SizesFor("gc", l.goarch), Error: func(err error) { addError(&pkg.Fact, err.Error()) }}
	if meta.Module != nil && meta.Module.GoVersion != "" {
		config.GoVersion = "go" + meta.Module.GoVersion
	}
	checked, err := config.Check(pkg.Fact.Path, l.fset, pkg.Files, pkg.Info)
	pkg.Types = checked
	if err != nil && !pkg.Fact.IllTyped {
		addError(&pkg.Fact, err.Error())
	}
	if checked != nil {
		l.pkgIDs[checked] = id
	}
	for _, file := range pkg.Files {
		if len(meta.CgoFiles) != 0 {
			source := l.exportSource(pkg, file)
			compiled := l.sources[l.fset.PositionFor(file.Pos(), false).Filename]
			if source != nil && source != compiled {
				l.rememberCgoFunctions(pkg, file, compiled, source)
				continue
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.FuncDecl:
				l.remember(pkg, node.Name, node)
			case *ast.TypeSpec:
				l.remember(pkg, node.Name, node)
			case *ast.ValueSpec:
				for _, name := range node.Names {
					l.remember(pkg, name, node)
				}
			case *ast.Field:
				for _, name := range node.Names {
					l.remember(pkg, name, node)
				}
			}
			return true
		})
	}
	return pkg
}

func (l *loader) discardSyntax(id string) {
	if pkg := l.checked[id]; pkg != nil {
		pkg.Info, pkg.Files = nil, nil
	}
}

func (l *loader) remember(pkg *checkedPackage, name *ast.Ident, decl ast.Node) {
	obj := pkg.Info.Defs[name]
	if obj == nil {
		return
	}
	pos := l.fset.PositionFor(name.Pos(), false)
	source := l.sources[pos.Filename]
	if source == nil || filepath.IsAbs(source.Path) {
		return
	}
	l.locations[obj] = &location{fileFact{source.Path, source.SHA256},
		l.fset.PositionFor(decl.Pos(), false).Offset, l.fset.PositionFor(decl.End(), false).Offset,
		pos.Offset, l.fset.PositionFor(name.End(), false).Offset}
}

type wrapperTypeKey struct {
	kind      string
	elem, key types.Type
	length    int64
	direction types.ChanDir
}

type exporter struct {
	loader     *loader
	out        *facts
	typeIDs    map[types.Type]int
	wrapperIDs map[wrapperTypeKey]int
	symIDs     map[types.Object]int
	err        error
}

func objectPackage(obj types.Object) string {
	if obj.Pkg() != nil {
		return obj.Pkg().Path()
	}
	return "builtin"
}

func (g *exporter) tuple(t *types.Tuple) []int {
	if t == nil {
		return nil
	}
	ids := make([]int, t.Len())
	for i := range ids {
		ids[i] = g.ref(t.At(i).Type())
	}
	return ids
}

func (g *exporter) ref(t types.Type) int {
	if t == nil || g.err != nil {
		return 0
	}
	if id := g.typeIDs[t]; id != 0 {
		return id
	}
	var key wrapperTypeKey
	switch t := t.(type) {
	case *types.Pointer:
		key = wrapperTypeKey{kind: "pointer", elem: t.Elem()}
	case *types.Slice:
		key = wrapperTypeKey{kind: "slice", elem: t.Elem()}
	case *types.Array:
		key = wrapperTypeKey{kind: "array", elem: t.Elem(), length: t.Len()}
	case *types.Map:
		key = wrapperTypeKey{kind: "map", key: t.Key(), elem: t.Elem()}
	case *types.Chan:
		key = wrapperTypeKey{kind: "channel", elem: t.Elem(), direction: t.Dir()}
	}
	// Basic leaves cannot change the consumer's ID-based cycle clipping.
	_, basicElem := key.elem.(*types.Basic)
	_, basicKey := key.key.(*types.Basic)
	if !basicElem || (key.kind == "map" && !basicKey) {
		key = wrapperTypeKey{}
	}
	if key.kind != "" {
		if id := g.wrapperIDs[key]; id != 0 {
			g.typeIDs[t] = id
			return id
		}
	}
	if len(g.out.Types) >= maxTypes || g.loader.ctx.Err() != nil {
		g.err = errors.New("type or execution budget exceeded")
		return 0
	}
	id := len(g.out.Types) + 1
	g.typeIDs[t] = id
	g.out.Types = append(g.out.Types, typeFact{ID: id, Kind: "unknown"})
	if key.kind != "" {
		if g.wrapperIDs == nil {
			g.wrapperIDs = make(map[wrapperTypeKey]int)
		}
		g.wrapperIDs[key] = id
	}
	row := typeFact{ID: id}
	switch t := t.(type) {
	case *types.Basic:
		row.Kind, row.Name = "builtin", t.Name()
	case *types.Named:
		row.Kind, row.Name, row.Package = "named", t.Obj().Name(), objectPackage(t.Obj())
		row.OriginSymbol = g.symbol(t.Origin().Obj())
		for i := 0; i < t.Origin().TypeParams().Len(); i++ {
			row.TypeParams = append(row.TypeParams, g.ref(t.Origin().TypeParams().At(i)))
		}
		row.Underlying = g.ref(t.Underlying())
		for i := 0; i < t.TypeArgs().Len(); i++ {
			row.Args = append(row.Args, g.ref(t.TypeArgs().At(i)))
		}
		for i := 0; i < t.NumMethods(); i++ {
			method := t.Method(i)
			if method.Exported() || g.loader.pkgIDs[method.Pkg()] != "" {
				row.Methods = append(row.Methods,
					memberFact{Name: method.Name(), Type: g.ref(method.Type()), Package: objectPackage(method)})
			}
		}
	case *types.Alias:
		row.Kind, row.Name, row.Package = "alias", t.Obj().Name(), objectPackage(t.Obj())
		row.OriginSymbol = g.symbol(t.Origin().Obj())
		for i := 0; i < t.Origin().TypeParams().Len(); i++ {
			row.TypeParams = append(row.TypeParams, g.ref(t.Origin().TypeParams().At(i)))
		}
		row.Underlying = g.ref(types.Unalias(t))
		for i := 0; i < t.TypeArgs().Len(); i++ {
			row.Args = append(row.Args, g.ref(t.TypeArgs().At(i)))
		}
	case *types.Pointer:
		row.Kind, row.Elem = "pointer", g.ref(t.Elem())
	case *types.Slice:
		row.Kind, row.Elem = "slice", g.ref(t.Elem())
	case *types.Array:
		row.Kind, row.Elem, row.Length = "array", g.ref(t.Elem()), t.Len()
	case *types.Map:
		row.Kind, row.Key, row.Elem = "map", g.ref(t.Key()), g.ref(t.Elem())
	case *types.Chan:
		row.Kind, row.Elem, row.Direction = "channel", g.ref(t.Elem()), int(t.Dir())
	case *types.Signature:
		row.Kind, row.Variadic = "signature", t.Variadic()
		row.Params, row.Returns = g.tuple(t.Params()), g.tuple(t.Results())
		if t.Recv() != nil {
			row.Receiver = g.ref(t.Recv().Type())
		}
	case *types.Struct:
		row.Kind = "struct"
		for i := 0; i < t.NumFields(); i++ {
			field := t.Field(i)
			if !field.Exported() && !field.Embedded() && g.loader.pkgIDs[field.Pkg()] == "" {
				continue
			}
			row.Fields = append(row.Fields, memberFact{field.Name(), g.ref(field.Type()),
				objectPackage(field), field.Embedded()})
			if field.Embedded() {
				row.Embeds = append(row.Embeds, g.ref(field.Type()))
			}
		}
	case *types.Interface:
		row.Kind = "interface"
		t.Complete()
		for i := 0; i < t.NumMethods(); i++ {
			method := t.Method(i)
			row.Methods = append(row.Methods, memberFact{
				Name: method.Name(), Type: g.ref(method.Type()), Package: objectPackage(method)})
		}
		for i := 0; i < t.NumEmbeddeds(); i++ {
			row.Embeds = append(row.Embeds, g.ref(t.EmbeddedType(i)))
		}
	case *types.TypeParam:
		row.Kind, row.Name, row.Underlying = "type_param", t.Obj().Name(), g.ref(t.Constraint())
	case *types.Tuple:
		row.Kind, row.Args = "tuple", g.tuple(t)
	case *types.Union:
		row.Kind = "union"
		for i := 0; i < t.Len(); i++ {
			row.Args = append(row.Args, g.ref(t.Term(i).Type()))
		}
	default:
		row.Kind = "unknown"
	}
	g.out.Types[id-1] = row
	return id
}

func (g *exporter) symbol(obj types.Object) int {
	if obj == nil || g.err != nil || obj.Name() == "_" {
		return 0
	}
	if fn, ok := obj.(*types.Func); ok {
		obj = fn.Origin()
	}
	if id := g.symIDs[obj]; id != 0 {
		return id
	}
	if len(g.out.Symbols) >= maxSymbols || g.loader.ctx.Err() != nil {
		g.err = errors.New("symbol or execution budget exceeded")
		return 0
	}
	loc := g.loader.locations[obj]
	internal := false
	if loc != nil {
		abs := filepath.Join(g.loader.root, filepath.FromSlash(loc.Path))
		source := g.loader.manifest[abs]
		internal = source != nil && source.SHA256 == loc.SHA256
	}
	pos := g.loader.fset.PositionFor(obj.Pos(), false)
	packageID := g.loader.pkgIDs[obj.Pkg()]
	if packageID != "" && loc == nil && g.loader.sources[pos.Filename] != nil &&
		filepath.IsAbs(g.loader.sources[pos.Filename].Path) {
		return 0
	}
	// Importer export data can name a replacement file inside the root.
	exportedReplacement := packageID == "" && g.loader.exportDeps[objectPackage(obj)]
	if filepath.IsAbs(pos.Filename) {
		rel, err := filepath.Rel(g.loader.root, pos.Filename)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) &&
			!filepath.IsAbs(rel) && !internal && !exportedReplacement {
			return 0
		}
	}
	row := symbolFact{ID: len(g.out.Symbols) + 1, Package: objectPackage(obj), Name: obj.Name(),
		Internal: internal, Declaration: loc, LocationStatus: "export_only"}
	if internal {
		row.LocationStatus = "exact"
	}
	row.PackageID = packageID
	var receiverType types.Type
	switch obj := obj.(type) {
	case *types.Func:
		row.Kind = "function"
		if receiver := obj.Type().(*types.Signature).Recv(); receiver != nil {
			row.Kind = "method"
			if isInterface(receiver.Type()) {
				row.Kind = "interface_method"
			}
			receiverType = receiver.Type()
		}
	case *types.TypeName:
		row.Kind = "type"
	case *types.Var:
		row.Kind = "global"
		if obj.IsField() {
			row.Kind = "field"
		} else if obj.Pkg() == nil || obj.Parent() != obj.Pkg().Scope() {
			return 0
		}
	default:
		return 0
	}
	// Register the identity before traversing recursive declaration types.
	g.symIDs[obj] = row.ID
	g.out.Symbols = append(g.out.Symbols, row)
	receiverID := g.ref(receiverType)
	typeID := g.ref(obj.Type())
	g.out.Symbols[row.ID-1].Receiver = receiverID
	g.out.Symbols[row.ID-1].Type = typeID
	return row.ID
}

func isInterface(t types.Type) bool {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	_, ok := t.Underlying().(*types.Interface)
	return ok
}

func callBase(expr ast.Expr) ast.Expr {
	for {
		switch node := expr.(type) {
		case *ast.ParenExpr:
			expr = node.X
		case *ast.IndexExpr:
			expr = node.X
		case *ast.IndexListExpr:
			expr = node.X
		default:
			return expr
		}
	}
}

func (g *exporter) handleFuncHandler(info *types.Info, call *ast.CallExpr, target *types.Func,
	selection *types.Selection) int {
	if len(call.Args) != 2 || target.Name() != "HandleFunc" {
		return 0
	}
	if http := g.loader.listed["net/http"]; http == nil || !http.Standard {
		return 0
	}
	if recv := target.Signature().Recv(); recv != nil {
		if selection == nil || selection.Kind() != types.MethodVal {
			return 0
		}
		pointer, ok := types.Unalias(recv.Type()).(*types.Pointer)
		if !ok {
			return 0
		}
		named, ok := types.Unalias(pointer.Elem()).(*types.Named)
		if !ok || named.Obj().Name() != "ServeMux" || objectPackage(named.Obj()) != "net/http" {
			return 0
		}
	}
	var obj types.Object
	// shortcut: variables and computed callbacks need independent value-flow proof.
	switch arg := callBase(call.Args[1]).(type) {
	case *ast.Ident:
		obj = info.Uses[arg]
	case *ast.SelectorExpr:
		obj = info.Uses[arg.Sel]
		if selected := info.Selections[arg]; selected != nil {
			if selected.Kind() != types.MethodVal {
				return 0
			}
			obj = selected.Obj()
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok || g.loader.locations[fn.Origin()] == nil {
		return 0
	}
	if recv := fn.Signature().Recv(); recv != nil && isInterface(recv.Type()) {
		return 0
	}
	if id := g.symbol(fn); id != 0 && g.out.Symbols[id-1].Internal {
		return id
	}
	return 0
}

type localCallable struct {
	target    *types.Func
	otherUses int
}

func (g *exporter) site(pkg *checkedPackage, source *sourceFile, call *ast.CallExpr,
	locals map[types.Object]localCallable) siteFact {
	info := pkg.Info
	row := siteFact{fileFact: fileFact{source.Path, source.SHA256}, PackageID: pkg.Fact.ID,
		Start:       g.loader.fset.PositionFor(call.Pos(), false).Offset,
		End:         g.loader.fset.PositionFor(call.End(), false).Offset,
		CalleeStart: g.loader.fset.PositionFor(call.Fun.Pos(), false).Offset,
		CalleeEnd:   g.loader.fset.PositionFor(call.Fun.End(), false).Offset,
		Dispatch:    "unknown", Type: g.ref(info.TypeOf(call.Fun))}
	for _, arg := range call.Args {
		row.Arguments = append(row.Arguments, g.ref(info.TypeOf(arg)))
	}
	base := callBase(call.Fun)
	var obj types.Object
	var name *ast.Ident
	var selection *types.Selection
	switch base := base.(type) {
	case *ast.Ident:
		name, obj = base, info.Uses[base]
		if local := locals[obj]; local.target != nil && local.otherUses == 0 {
			obj = local.target
		}
	case *ast.SelectorExpr:
		name, obj = base.Sel, info.Uses[base.Sel]
		if selection = info.Selections[base]; selection != nil {
			obj = selection.Obj()
			row.Receiver = g.ref(selection.Recv())
		}
	}
	if name != nil {
		if instance, ok := info.Instances[name]; ok {
			for i := 0; i < instance.TypeArgs.Len(); i++ {
				row.Args = append(row.Args, g.ref(instance.TypeArgs.At(i)))
			}
		}
	}
	switch obj := obj.(type) {
	case *types.Func:
		row.Dispatch = "static"
		if recv := obj.Type().(*types.Signature).Recv(); recv != nil && isInterface(recv.Type()) {
			row.Dispatch = "interface"
		}
	case *types.Var:
		row.Dispatch = "function_value"
	case *types.Builtin:
		row.Dispatch = "builtin"
	}
	if info.Types[call.Fun].IsType() {
		row.Dispatch = "conversion"
	} else if row.Dispatch == "unknown" {
		if _, ok := info.TypeOf(call.Fun).(*types.Signature); ok {
			row.Dispatch = "function_value"
		}
	}
	if obj != nil {
		row.TargetPackage = objectPackage(obj)
		row.TargetSymbol = g.symbol(obj)
		if row.Dispatch == "static" && row.TargetSymbol == 0 {
			row.Dispatch, row.Reason = "unknown", "declaration_not_admitted"
		}
	}
	if pkg.Fact.IllTyped {
		row.Dispatch, row.Reason, row.TargetSymbol = "unknown", "ill_typed_package", 0
	} else if row.Dispatch == "static" && row.TargetPackage == "net/http" &&
		!g.out.Symbols[row.TargetSymbol-1].Internal {
		row.HandlerSymbol = g.handleFuncHandler(info, call, obj.(*types.Func), selection)
	}
	return row
}

func (l *loader) exportSource(pkg *checkedPackage, file *ast.File) *sourceFile {
	source := l.sources[l.fset.PositionFor(file.Pos(), false).Filename]
	if source == nil || l.manifest[source.Abs] != nil {
		return source
	}
	if len(pkg.Meta.CgoFiles) == 0 ||
		!bytes.HasPrefix(source.Data, []byte("// Code generated by cmd/cgo; DO NOT EDIT.\n\n//line ")) {
		return nil
	}
	original := l.fset.PositionFor(file.Package, true).Filename
	name, err := filepath.Rel(pkg.Meta.Dir, original)
	if err != nil || !slices.Contains(pkg.Meta.CgoFiles, name) {
		return nil
	}
	admitted := l.manifest[original]
	// User-authored line directives make the generated source mapping ambiguous.
	if admitted == nil || bytes.Contains(admitted.Data, []byte("//line ")) ||
		bytes.Contains(admitted.Data, []byte("/*line ")) {
		return nil
	}
	return admitted
}

func (l *loader) rememberCgoFunctions(pkg *checkedPackage, generated *ast.File, compiled, source *sourceFile) {
	positions := token.NewFileSet()
	original, err := parser.ParseFile(positions, source.Abs, source.Data, parser.SkipObjectResolution)
	if err != nil {
		return
	}
	type position struct{ line, column int }
	functions := make(map[position]*ast.FuncDecl)
	for _, declaration := range original.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Body != nil {
			name := positions.PositionFor(fn.Name.Pos(), false)
			functions[position{name.Line, name.Column}] = fn
		}
	}
	for _, declaration := range generated.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := l.fset.PositionFor(fn.Name.Pos(), true)
		match := functions[position{name.Line, name.Column}]
		obj := pkg.Info.Defs[fn.Name]
		if name.Filename != source.Abs || match == nil || obj == nil || fn.Name.Name != match.Name.Name {
			continue
		}
		start := positions.PositionFor(match.Pos(), false).Offset
		signatureEnd := positions.PositionFor(match.Body.Lbrace, false).Offset
		compiledStart := l.fset.PositionFor(fn.Pos(), false).Offset
		compiledEnd := l.fset.PositionFor(fn.Body.Lbrace, false).Offset
		if !bytes.Equal(source.Data[start:signatureEnd], compiled.Data[compiledStart:compiledEnd]) {
			continue
		}
		l.locations[obj] = &location{fileFact{source.Path, source.SHA256}, start,
			positions.PositionFor(match.End(), false).Offset,
			positions.PositionFor(match.Name.Pos(), false).Offset,
			positions.PositionFor(match.Name.End(), false).Offset}
	}
}

var cgoLineSplice = regexp.MustCompile(`(?:\\|\?\?/)[\t ]*\r?\n`)
var cgoLineControl = regexp.MustCompile(`(?m)(?:^|/\*|\*/|//)[\t\v\f ]*(?:#|%:|\?\?=)[\t\v\f ]*(?:line\b|[0-9]|/\*)`)

type cgoTarget struct {
	declaration location
	external    bool
	preamble    bool
	forward     bool
}

// cgo's package archive contains the native wrapper objects that supplied the
// selected export data. Read their C declaration locations without rerunning CC.
func (l *loader) cgoDeclarations(meta *listPackage) map[string]cgoTarget {
	if !l.cgoHeaders || meta.Export == "" {
		return nil
	}
	var objcFiles []string
	if runtime.GOOS == "darwin" {
		objcFiles = meta.MFiles
	}
	// C line control can make unrelated physical declarations share a DWARF location.
	for _, name := range slices.Concat(meta.CgoFiles, meta.HFiles, objcFiles) {
		source, err := l.source(name, meta.Dir)
		if err != nil || cgoLineControl.Match(cgoLineSplice.ReplaceAll(source.Data, nil)) {
			return nil
		}
	}
	archive, err := os.Open(meta.Export)
	if err != nil {
		return nil
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil || info.Size() > 256<<20 {
		return nil
	}
	var magic [8]byte
	if _, err := io.ReadFull(archive, magic[:]); err != nil || string(magic[:]) != "!<arch>\n" {
		return nil
	}
	targets := make(map[string]cgoTarget)
	var definitions map[string]cgoTarget
	if len(objcFiles) != 0 {
		definitions = make(map[string]cgoTarget)
	}
	for offset := int64(len(magic)); offset < info.Size(); {
		var header [60]byte
		if l.ctx.Err() != nil {
			return nil
		}
		if _, err := archive.ReadAt(header[:], offset); err != nil || string(header[58:]) != "`\n" {
			return nil
		}
		offset += int64(len(header))
		size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || size < 0 || size > info.Size()-offset {
			return nil
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		if strings.HasPrefix(name, "_x") && strings.HasSuffix(name, ".o") && size <= 8<<20 {
			if data := cgoObjectDWARF(io.NewSectionReader(archive, offset, size), runtime.GOOS); data != nil {
				l.cgoObjectDeclarations(meta, data, runtime.GOOS == "darwin", targets, definitions)
			}
		}
		offset += size + (size & 1)
	}
	for name, target := range targets {
		if target.forward {
			targets[name] = definitions[name]
		}
	}
	return targets
}

func cgoObjectDWARF(source io.ReaderAt, goos string) *dwarf.Data {
	var total uint64
	if goos == "darwin" {
		object, err := macho.NewFile(source)
		if err != nil || object.Type != macho.TypeObj {
			return nil
		}
		defer object.Close()
		for _, section := range object.Sections {
			if strings.HasPrefix(section.Name, "__zdebug_") || section.Size > 8<<20-total {
				return nil
			}
			total += section.Size
		}
		data, _ := object.DWARF()
		return data
	}
	object, err := elf.NewFile(source)
	if err != nil {
		return nil
	}
	defer object.Close()
	for _, section := range object.Sections {
		if section.Size > 8<<20-total {
			return nil
		}
		total += section.Size
	}
	data, _ := object.DWARF()
	return data
}

func (l *loader) cgoObjectDeclarations(meta *listPackage, data *dwarf.Data, machoObject bool,
	targets, definitions map[string]cgoTarget) {
	reader := data.Reader()
	var lines *dwarf.LineReader
	var stack []*dwarf.Entry
	for l.ctx.Err() == nil {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			return
		}
		if entry.Tag == 0 {
			if len(stack) == 0 {
				return
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if entry.Tag == dwarf.TagCompileUnit {
			lines, _ = data.LineReader(entry)
		}
		if definitions != nil && lines != nil && entry.Tag == dwarf.TagSubprogram &&
			entry.Val(dwarf.AttrExternal) == true && entry.Val(dwarf.AttrDeclaration) != true &&
			(entry.Val(dwarf.AttrLowpc) != nil || entry.Val(dwarf.AttrRanges) != nil) {
			name, _ := entry.Val(dwarf.AttrName).(string)
			linkage, _ := entry.Val(dwarf.AttrLinkageName).(string)
			path := cgoDeclarationPath(lines, entry)
			if name != "" && (linkage == "" || linkage == name) &&
				strings.HasSuffix(path, ".m") && filepath.Dir(path) == meta.Dir &&
				slices.Contains(meta.MFiles, filepath.Base(path)) {
				target := l.cgoLocation(entry, path, name, true)
				if _, duplicate := definitions[name]; duplicate {
					target = cgoTarget{}
				}
				definitions[name] = target
			}
		}
		if lines != nil && len(stack) != 0 &&
			(entry.Tag == dwarf.TagCallSite || entry.Tag == dwarf.TagInlinedSubroutine) {
			parent := stack[len(stack)-1]
			wrapper, _ := parent.Val(dwarf.AttrName).(string)
			name, valid := cgoWrapperName(wrapper)
			if valid && parent.Tag == dwarf.TagSubprogram {
				attribute := dwarf.AttrCallOrigin
				if entry.Tag == dwarf.TagInlinedSubroutine {
					attribute = dwarf.AttrAbstractOrigin
				}
				if offset, ok := entry.Val(attribute).(dwarf.Offset); ok {
					target, matched := l.cgoDeclaration(meta, data, lines, name, offset, machoObject)
					if matched {
						if previous, found := targets[name]; found && previous != target {
							target = cgoTarget{}
						}
						targets[name] = target
					}
				}
			}
		}
		if entry.Children {
			stack = append(stack, entry)
		}
	}
}

func cgoWrapperName(wrapper string) (string, bool) {
	prefix, name, found := strings.Cut(wrapper, "_Cfunc_")
	hash, cgo := strings.CutPrefix(prefix, "_cgo_")
	return name, found && cgo && len(hash) == 12 && strings.Trim(hash, "0123456789abcdef") == ""
}

func cgoDeclarationPath(lines *dwarf.LineReader, decl *dwarf.Entry) string {
	index, ok := decl.Val(dwarf.AttrDeclFile).(int64)
	files := lines.Files()
	if !ok || index < 0 || index >= int64(len(files)) || files[index] == nil {
		return ""
	}
	path := filepath.Clean(files[index].Name)
	if !filepath.IsAbs(path) {
		return ""
	}
	return path
}

func (l *loader) cgoDeclaration(meta *listPackage, data *dwarf.Data, lines *dwarf.LineReader,
	name string, offset dwarf.Offset, machoObject bool) (cgoTarget, bool) {
	reader := data.Reader()
	reader.Seek(offset)
	decl, err := reader.Next()
	if err != nil || decl == nil || decl.Tag != dwarf.TagSubprogram || decl.Val(dwarf.AttrName) != name {
		return cgoTarget{}, false
	}
	path := cgoDeclarationPath(lines, decl)
	line, _ := decl.Val(dwarf.AttrDeclLine).(int64)
	column, _ := decl.Val(dwarf.AttrDeclColumn).(int64)
	if path == "" || line <= 0 || (!machoObject && column <= 0) {
		return cgoTarget{}, true
	}
	nameInPackage := filepath.Base(path)
	preamble := strings.HasSuffix(path, ".go") && slices.Contains(meta.CgoFiles, nameInPackage)
	header := strings.HasSuffix(path, ".h") && slices.Contains(meta.HFiles, nameInPackage)
	if decl.Val(dwarf.AttrDeclaration) == true {
		_, local := within(l.root, path)
		// A local forward declaration needs a unique compiled definition from this package.
		if machoObject && decl.Val(dwarf.AttrExternal) == true &&
			filepath.Dir(path) == meta.Dir && (preamble || header) &&
			l.cgoLocation(decl, path, name, true) != (cgoTarget{}) {
			return cgoTarget{forward: true}, true
		}
		// The SDK declaration proves external linkage, without naming a library or implementation.
		return cgoTarget{external: !local && strings.HasSuffix(path, ".h") &&
			decl.Val(dwarf.AttrExternal) == true}, true
	}
	if filepath.Dir(path) != meta.Dir || (!preamble && !header) {
		return cgoTarget{}, true
	}
	target := l.cgoLocation(decl, path, name, machoObject)
	target.preamble = preamble && target != (cgoTarget{})
	return target, true
}

func (l *loader) cgoLocation(decl *dwarf.Entry, path, name string, machoObject bool) cgoTarget {
	line, _ := decl.Val(dwarf.AttrDeclLine).(int64)
	column, _ := decl.Val(dwarf.AttrDeclColumn).(int64)
	source := l.manifest[path]
	if source == nil || line <= 0 || line > int64(len(source.Data)) ||
		column > int64(len(source.Data)) || (!machoObject && column <= 0) {
		return cgoTarget{}
	}
	start := 0
	for i := int64(1); i < line; i++ {
		newline := bytes.IndexByte(source.Data[start:], '\n')
		if newline < 0 {
			return cgoTarget{}
		}
		start += newline + 1
	}
	lineEnd := bytes.IndexByte(source.Data[start:], '\n')
	if lineEnd < 0 {
		lineEnd = len(source.Data) - start
	}
	if column <= 0 {
		// Apple clang omits DW_AT_decl_column. Require one spelling on the proven declaration line.
		declaration := source.Data[start : start+lineEnd]
		pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `[	 ]*\(`)
		matches := pattern.FindAllIndex(declaration, 2)
		if len(matches) != 1 {
			return cgoTarget{}
		}
		column = int64(matches[0][0] + 1)
	}
	start += int(column) - 1
	end := start + len(name)
	if int(column)-1+len(name) > lineEnd || string(source.Data[start:end]) != name {
		return cgoTarget{}
	}
	return cgoTarget{declaration: location{fileFact{source.Path, source.SHA256}, start, end, start, end}}
}

func (g *exporter) exportCgoFile(pkg *checkedPackage, generated *ast.File, source *sourceFile, maxSites int) {
	original, err := parser.ParseFile(g.loader.fset, source.Abs, source.Data, parser.SkipObjectResolution)
	if err != nil {
		return
	}
	type position struct{ line, column int }
	type target struct {
		fn       *types.Func
		selector string
		dispatch string
	}
	mapped := make(map[position]target)
	conversions := make(map[position]string)
	type nativePosition struct {
		position
		end bool
	}
	nativeCalls := make(map[nativePosition]string)
	toolchainCalls := make(map[nativePosition]bool)
	fs := g.loader.fset
	generatedSource := g.loader.sources[fs.PositionFor(generated.Pos(), false).Filename]
	ast.Inspect(generated, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return g.loader.ctx.Err() == nil
		}
		if g.loader.cgoHeaders {
			if id, ok := callBase(call.Fun).(*ast.Ident); ok {
				name, wrapper := strings.CutPrefix(id.Name, "_Cfunc_")
				fn, bound := pkg.Info.Uses[id].(*types.Func)
				pos := fs.PositionFor(id.Pos(), true)
				if wrapper && bound && fn.Pkg() == pkg.Types && pos.Filename == source.Abs && pos.Column != 0 {
					_, direct := call.Fun.(*ast.ParenExpr)
					key := nativePosition{position{pos.Line, pos.Column}, !direct}
					if runtime.GOOS == "darwin" {
						switch name {
						case "CString", "CBytes", "GoString", "GoStringN", "GoBytes", "_CMalloc":
							source := g.loader.sources[fs.PositionFor(fn.Pos(), false).Filename]
							if source != nil && bytes.HasPrefix(source.Data, []byte("// Code generated by cmd/cgo; DO NOT EDIT.")) &&
								g.loader.manifest[source.Abs] == nil {
								toolchainCalls[key] = true
								if name == "_CMalloc" {
									name = "malloc"
								}
							}
						}
					}
					if _, duplicate := nativeCalls[key]; duplicate {
						name = ""
						delete(toolchainCalls, key)
					}
					nativeCalls[key] = name
					return true
				}
			}
		}
		if id, ok := call.Fun.(*ast.Ident); ok && pkg.Info.Types[id].IsType() {
			if suffix, ok := strings.CutPrefix(id.Name, "_Ctype_"); ok {
				// cgo pointer checks can move the type token and preserve only its opening parenthesis.
				pos := fs.PositionFor(call.Lparen, true)
				if pos.Filename == source.Abs && pos.Column != 0 {
					key := position{pos.Line, pos.Column}
					if _, duplicate := conversions[key]; duplicate {
						conversions[key] = ""
					} else {
						conversions[key] = "C." + suffix
					}
				}
			}
		}
		pos := fs.PositionFor(call.Fun.Pos(), true)
		if pos.Filename != source.Abs || pos.Column == 0 {
			return true
		}
		key := position{pos.Line, pos.Column}
		if _, duplicate := mapped[key]; duplicate {
			mapped[key] = target{}
			return true
		}
		mapped[key] = target{}
		if name, ok := call.Fun.(*ast.Ident); ok {
			if pkg.Info.Types[name].IsType() {
				if suffix, ok := strings.CutPrefix(name.Name, "_Ctype_"); ok {
					mapped[key] = target{selector: "C." + suffix, dispatch: "conversion"}
				}
			} else if variable, ok := pkg.Info.Uses[name].(*types.Var); ok {
				if _, callable := variable.Type().Underlying().(*types.Signature); callable {
					mapped[key] = target{selector: name.Name, dispatch: "function_value"}
				}
			}
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		fn, isFunc := pkg.Info.Uses[selector.Sel].(*types.Func)
		if !isFunc || !fn.Exported() || g.loader.pkgIDs[fn.Pkg()] != "" {
			return true
		}
		if method := pkg.Info.Selections[selector]; method != nil {
			receiver := fn.Type().(*types.Signature).Recv()
			if method.Kind() != types.MethodVal || method.Obj() != fn ||
				receiver == nil || isInterface(receiver.Type()) || isInterface(method.Recv()) {
				return true
			}
		} else {
			qualifier, _ := selector.X.(*ast.Ident)
			dependency, ok := pkg.Info.Uses[qualifier].(*types.PkgName)
			if !ok || dependency.Imported() != fn.Pkg() {
				return true
			}
		}
		start := fs.PositionFor(selector.Pos(), false).Offset
		end := fs.PositionFor(selector.End(), false).Offset
		mapped[key] = target{fn: fn, selector: string(generatedSource.Data[start:end]), dispatch: "static"}
		return true
	})
	if len(nativeCalls) != 0 && pkg.CgoDeclarations == nil {
		pkg.CgoDeclarations = g.loader.cgoDeclarations(pkg.Meta)
		if pkg.CgoDeclarations == nil {
			pkg.CgoDeclarations = map[string]cgoTarget{}
		}
	}
	ast.Inspect(original, func(node ast.Node) bool {
		if g.err != nil || g.loader.ctx.Err() != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		pos := fs.PositionFor(call.Fun.Pos(), false)
		target := mapped[position{pos.Line, pos.Column}]
		end := fs.PositionFor(call.Fun.End(), false).Offset
		callee := string(source.Data[pos.Offset:end])
		callEnd := fs.PositionFor(call.End(), false)
		if target.selector == "" {
			calleeEnd := fs.PositionFor(call.Fun.End(), false)
			if conversions[position{calleeEnd.Line, calleeEnd.Column}] == callee {
				target.selector, target.dispatch = callee, "conversion"
			}
		}
		var native cgoTarget
		nativeName, isC := strings.CutPrefix(callee, "C.")
		if isC {
			from := nativePosition{position{pos.Line, pos.Column}, false}
			to := nativePosition{position{callEnd.Line, callEnd.Column}, true}
			startMatch, endMatch := nativeCalls[from] == nativeName, nativeCalls[to] == nativeName
			if startMatch != endMatch {
				native = pkg.CgoDeclarations[nativeName]
				if (startMatch && toolchainCalls[from]) || (endMatch && toolchainCalls[to]) {
					native = cgoTarget{external: true}
				}
				if native.preamble && native.declaration.Path != source.Path {
					native = cgoTarget{}
				}
			}
		}
		if native == (cgoTarget{}) && (target.selector == "" || target.selector != callee) {
			return true
		}
		if len(g.out.Sites) >= maxSites {
			g.err = errors.New("call site budget exceeded")
			return false
		}
		row := siteFact{
			fileFact: fileFact{source.Path, source.SHA256}, PackageID: pkg.Fact.ID,
			Start: fs.PositionFor(call.Pos(), false).Offset, End: callEnd.Offset,
			CalleeStart: pos.Offset, CalleeEnd: end, Dispatch: target.dispatch,
		}
		if native != (cgoTarget{}) {
			if len(g.out.Symbols) >= maxSymbols {
				g.err = errors.New("symbol budget exceeded")
				return false
			}
			row.Dispatch = "static"
			row.TargetSymbol = len(g.out.Symbols) + 1
			symbol := symbolFact{ID: row.TargetSymbol, Kind: "function", Name: nativeName}
			if native.external {
				symbol.Package, symbol.LocationStatus = "C", "cgo_external"
			} else {
				symbol.Package, symbol.PackageID = pkg.Fact.Path, pkg.Fact.ID
				symbol.Internal, symbol.Declaration, symbol.LocationStatus = true, &native.declaration, "cgo_native"
				if native.preamble {
					symbol.LocationStatus = "cgo_preamble"
				}
			}
			row.TargetPackage = symbol.Package
			g.out.Symbols = append(g.out.Symbols, symbol)
		} else if target.fn != nil {
			row.TargetSymbol = g.symbol(target.fn)
			if row.TargetSymbol == 0 {
				return true
			}
			row.TargetPackage = target.fn.Pkg().Path()
		}
		g.out.Sites = append(g.out.Sites, row)
		return true
	})
}

func (g *exporter) exportFile(pkg *checkedPackage, file *ast.File, source *sourceFile, maxSites int) {
	if len(pkg.Meta.CgoFiles) != 0 && g.loader.fset.PositionFor(file.Pos(), false).Filename != source.Abs {
		g.exportCgoFile(pkg, file, source, maxSites)
		return
	}
	info := pkg.Info
	locals := make(map[types.Object]localCallable)
	countRead := func(expr ast.Expr) {
		if name, ok := expr.(*ast.Ident); ok {
			obj := info.Uses[name]
			if local, ok := locals[obj]; ok {
				local.otherUses--
				locals[obj] = local
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if g.err != nil || g.loader.ctx.Err() != nil {
			return false
		}
		// shortcut: only direct short declarations with callee and bare argument reads;
		// following assignments or other uses requires value-flow proof.
		switch node := node.(type) {
		case *ast.AssignStmt:
			if pkg.Fact.IllTyped || node.Tok != token.DEFINE || len(node.Lhs) != 1 || len(node.Rhs) != 1 {
				break
			}
			name, _ := node.Lhs[0].(*ast.Ident)
			if name == nil || name.Name == "_" || info.Defs[name] == nil {
				break
			}
			var obj types.Object
			switch rhs := callBase(node.Rhs[0]).(type) {
			case *ast.Ident:
				obj = info.Uses[rhs]
			case *ast.SelectorExpr:
				obj = info.Uses[rhs.Sel]
				if selection := info.Selections[rhs]; selection != nil {
					obj = selection.Obj()
				}
			}
			if literal, ok := ast.Unparen(node.Rhs[0]).(*ast.FuncLit); ok {
				if signature, ok := info.TypeOf(literal).(*types.Signature); ok {
					// The anonymous declaration is anchored by its func keyword.
					fn := types.NewFunc(literal.Pos(), pkg.Types, "func", signature)
					start := g.loader.fset.PositionFor(literal.Pos(), false).Offset
					end := g.loader.fset.PositionFor(literal.End(), false).Offset
					g.loader.locations[fn] = &location{fileFact{source.Path, source.SHA256},
						start, end, start, start + len(fn.Name())}
					obj = fn
				}
			}
			if fn, ok := obj.(*types.Func); ok {
				if recv := fn.Signature().Recv(); recv == nil || !isInterface(recv.Type()) {
					locals[info.Defs[name]] = localCallable{target: fn}
				}
			}
		case *ast.CallExpr:
			countRead(callBase(node.Fun))
			// Passing a function value copies it, so the callee cannot rebind this local.
			for _, arg := range node.Args {
				countRead(ast.Unparen(arg))
			}
		case *ast.Ident:
			g.symbol(info.Defs[node])
			obj := info.Uses[node]
			if local, ok := locals[obj]; ok {
				local.otherUses++
				locals[obj] = local
			}
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		if g.err != nil || g.loader.ctx.Err() != nil {
			return false
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if len(g.out.Sites) >= maxSites {
				g.err = errors.New("call site budget exceeded")
				return false
			}
			g.out.Sites = append(g.out.Sites, g.site(pkg, source, call, locals))
		}
		return true
	})
}

func addConfig(paths map[string]string, path string) error {
	if path == "" || path == "off" || path == os.DevNull {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	data, err := readLimited(abs, 8<<20)
	value := "missing"
	if os.IsNotExist(err) {
		err = nil
	} else if err == nil {
		value = digest(data)
	}
	if err != nil {
		return err
	}
	key := filepath.ToSlash(abs)
	if previous, ok := paths[key]; ok && previous != value {
		return fmt.Errorf("configuration changed during analysis: %s", path)
	}
	paths[key] = value
	return nil
}

func snapshotUnchanged(ctx context.Context, sources map[string]*sourceFile) error {
	return checkPaths(ctx, sources, func(path string, source *sourceFile) error {
		current, err := digestFile(path)
		if err != nil || current != source.SHA256 {
			return fmt.Errorf("source changed during analysis: %s", source.Path)
		}
		return nil
	})
}

func checkPaths[T any](ctx context.Context, paths map[string]T, check func(string, T) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	jobs := make(chan string)
	var workers sync.WaitGroup
	// Resolving each path can require several filesystem calls on Windows.
	for range min(8, len(paths)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for path := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := check(path, paths[path]); err != nil {
					cancel(err)
					return
				}
			}
		}()
	}
dispatch:
	for path := range paths {
		select {
		case jobs <- path:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	return context.Cause(ctx)
}

func identitiesUnchanged(ctx context.Context, paths map[string]string) error {
	return checkPaths(ctx, paths, func(path, previous string) error {
		current, err := canonical(path)
		if err != nil || current != previous {
			return fmt.Errorf("compiler input identity changed during analysis: %s", path)
		}
		return nil
	})
}

func inputsUnchanged(ctx context.Context, paths map[string]string) error {
	return checkPaths(ctx, paths, func(path, previous string) error {
		current, err := digestFile(path)
		if os.IsNotExist(err) && previous == "missing" {
			return nil
		}
		if err != nil || current != previous {
			return fmt.Errorf("compiler input changed during analysis: %s", path)
		}
		return nil
	})
}

func validateOptions(opts options) error {
	if opts.ChunkIndexV2 && (opts.Cache == "" || opts.PackageIndex || opts.ChunkIndex) {
		return errors.New("chunk index v2 requires --cache and excludes other index modes")
	}
	if opts.PackageIndex && opts.Cache == "" {
		return errors.New("package index mode requires --cache")
	}
	if opts.ChunkIndex && (opts.Cache == "" || opts.PackageIndex) {
		return errors.New("chunk index mode requires --cache and excludes --package-index")
	}
	if opts.BudgetMS <= 0 || opts.BudgetMS > maxBudgetMS ||
		opts.MaxSites <= 0 || opts.MaxSites > maxCallSites ||
		opts.MaxBytes < 1024 || opts.MaxBytes > maxJSONBytes {
		return errors.New("budgets must be 1..300000 ms, 1..100000 sites and 1024..33554432 JSON bytes")
	}
	if len(opts.Patterns) == 0 || len(opts.Patterns) > 256 {
		return errors.New("package pattern budget must be 1..256")
	}
	for _, pattern := range opts.Patterns {
		if pattern == "" || len(pattern) > 4096 || strings.TrimSpace(pattern) != pattern ||
			strings.HasPrefix(pattern, "-") {
			return fmt.Errorf("invalid package pattern %q", pattern)
		}
	}
	return nil
}

type packageCache struct {
	Key, HelperSHA256, PayloadSHA256 string
	Package                          packageFact
	Types                            []typeFact
	Symbols                          []symbolFact
	Sites                            []siteFact
}

func (entry packageCache) payloadHash() string {
	entry.Key, entry.HelperSHA256, entry.PayloadSHA256 = "", "", ""
	return digestJSON(entry)
}

func packageKeys(l *loader, base string, exports map[string]string) map[string]string {
	keys, active := make(map[string]string), make(map[string]bool)
	var key func(string) string
	key = func(id string) string {
		if l.ctx.Err() != nil {
			return ""
		}
		if value, ok := keys[id]; ok {
			return value
		}
		meta := l.listed[id]
		if meta == nil || active[id] || meta.Error != nil || len(meta.DepsErrors) != 0 {
			return ""
		}
		active[id] = true
		defer delete(active, id)
		dependencies := make(map[string]string)
		for _, imported := range meta.Imports {
			dependency := imported
			if mapped := meta.ImportMap[imported]; mapped != "" {
				dependency = mapped
			}
			value := key(dependency)
			if dependency == "unsafe" {
				value = "builtin"
			}
			if value == "" {
				keys[id] = ""
				return ""
			}
			dependencies[dependency] = value
		}
		inputs := make(map[string]string)
		admitted := make(map[string]bool)
		dir, err := l.canonicalInput(meta.Dir)
		if err != nil {
			keys[id] = ""
			return ""
		}
		if _, own := within(l.root, dir); own {
			paths := meta.CompiledGoFiles
			if len(paths) == 0 {
				paths = meta.GoFiles
			}
			for _, path := range slices.Concat(paths, meta.CgoFiles) {
				source, err := l.source(path, meta.Dir)
				if err != nil {
					keys[id] = ""
					return ""
				}
				// Include both selected spelling and resolved identity: a
				// symlink retarget must invalidate an otherwise equal source.
				selected := path
				if !filepath.IsAbs(selected) {
					selected = filepath.Join(meta.Dir, selected)
				}
				inputs[filepath.ToSlash(selected)] = source.Abs + ":" + source.SHA256
				admitted[source.Abs] = l.manifest[source.Abs] != nil
			}
			if l.cgoHeaders && len(meta.CgoFiles) != 0 {
				nativeFiles := meta.HFiles
				if runtime.GOOS == "darwin" {
					nativeFiles = slices.Concat(nativeFiles, meta.MFiles)
				}
				for _, name := range nativeFiles {
					if source := l.manifest[filepath.Join(dir, name)]; source != nil {
						inputs[source.Path] = source.SHA256
					}
				}
			}
		} else if exports[id] == "" || exports[id] == "missing" {
			keys[id] = ""
			return ""
		}
		keys[id] = digestJSON(struct {
			Base, ID, Dir, Name, ForTest, Export string
			Module                               *module
			Inputs                               map[string]string
			Admitted                             map[string]bool
			ImportMap                            map[string]string
			Dependencies                         map[string]string
		}{base, id, filepath.ToSlash(dir), meta.Name, meta.ForTest, exports[id],
			meta.Module, inputs, admitted, meta.ImportMap, dependencies})
		return keys[id]
	}
	for id := range l.listed {
		key(id)
	}
	return keys
}

func validPackageCache(entry packageCache, l *loader, meta *listPackage, key, helper string, maxSites int) bool {
	return entry.PayloadSHA256 == entry.payloadHash() &&
		validPackageContent(entry, l, meta, key, helper, maxSites)
}

func validPackageContent(entry packageCache, l *loader, meta *listPackage, key, helper string, maxSites int) bool {
	if key == "" || entry.Key != key || entry.HelperSHA256 != helper ||
		entry.Package.ID != meta.ImportPath || entry.Package.Path != packagePath(meta.ImportPath) ||
		entry.Package.Dir != filepath.ToSlash(meta.Dir) || entry.Package.Name != meta.Name ||
		entry.Package.ForTest != meta.ForTest || entry.Package.IllTyped || len(entry.Package.Errors) != 0 ||
		len(entry.Types) > maxTypes || len(entry.Symbols) > maxSymbols || len(entry.Sites) > maxSites {
		return false
	}
	typeRef := func(id int) bool { return id >= 0 && id <= len(entry.Types) }
	symbolRef := func(id int) bool { return id >= 0 && id <= len(entry.Symbols) }
	span := func(path, hash string, start, end int) *sourceFile {
		source := l.manifest[filepath.Join(l.root, filepath.FromSlash(path))]
		if source == nil || source.Path != path || source.SHA256 != hash ||
			start < 0 || start >= end || end > len(source.Data) {
			return nil
		}
		return source
	}
	for i, row := range entry.Types {
		if row.ID != i+1 || !symbolRef(row.OriginSymbol) ||
			!typeRef(row.Underlying) || !typeRef(row.Elem) ||
			!typeRef(row.Key) || !typeRef(row.Receiver) {
			return false
		}
		switch row.Kind {
		case "unknown", "builtin", "named", "alias", "pointer", "slice", "array", "map",
			"channel", "signature", "struct", "interface", "type_param", "tuple", "union":
		default:
			return false
		}
		for _, refs := range [][]int{row.Params, row.Returns, row.TypeParams, row.Args, row.Embeds} {
			for _, id := range refs {
				if !typeRef(id) {
					return false
				}
			}
		}
		for _, id := range row.TypeParams {
			if id == 0 || entry.Types[id-1].Kind != "type_param" {
				return false
			}
		}
		if row.OriginSymbol != 0 {
			origin := entry.Symbols[row.OriginSymbol-1]
			if (row.Kind != "named" && row.Kind != "alias") || origin.Kind != "type" ||
				origin.Name != row.Name || origin.Package != row.Package {
				return false
			}
		}
		for _, members := range [][]memberFact{row.Fields, row.Methods} {
			for _, member := range members {
				if member.Name == "" || !typeRef(member.Type) {
					return false
				}
			}
		}
	}
	for i, row := range entry.Symbols {
		if row.ID != i+1 || row.Name == "" || row.Package == "" ||
			!typeRef(row.Type) || !typeRef(row.Receiver) {
			return false
		}
		if row.PackageID != "" {
			pkg := l.listed[row.PackageID]
			if pkg == nil || packagePath(pkg.ImportPath) != row.Package {
				return false
			}
		}
		switch row.Kind {
		case "function", "method", "interface_method", "type", "global", "field":
		default:
			return false
		}
		if row.Internal {
			loc := row.Declaration
			if loc == nil || (row.LocationStatus != "exact" &&
				!(l.cgoHeaders && ((row.LocationStatus == "cgo_native" && cgoNativeSource(loc.Path)) ||
					(row.LocationStatus == "cgo_preamble" && strings.HasSuffix(loc.Path, ".go"))) &&
					row.Kind == "function" && row.PackageID == meta.ImportPath &&
					row.Type == 0 && row.Receiver == 0)) {
				return false
			}
			source := span(loc.Path, loc.SHA256, loc.Start, loc.End)
			if source == nil || loc.NameStart < loc.Start || loc.NameEnd > loc.End ||
				loc.NameStart >= loc.NameEnd || string(source.Data[loc.NameStart:loc.NameEnd]) != row.Name {
				return false
			}
		} else if row.Declaration != nil || (row.LocationStatus != "export_only" &&
			!(l.cgoHeaders && row.LocationStatus == "cgo_external" && row.Package == "C" &&
				row.PackageID == "" && row.Kind == "function" && row.Type == 0 && row.Receiver == 0)) {
			return false
		}
	}
	for _, row := range entry.Sites {
		if row.PackageID != meta.ImportPath ||
			span(row.Path, row.SHA256, row.Start, row.End) == nil ||
			row.CalleeStart < row.Start || row.CalleeEnd > row.End || row.CalleeStart >= row.CalleeEnd ||
			!typeRef(row.Type) || !typeRef(row.Receiver) || !symbolRef(row.TargetSymbol) ||
			!symbolRef(row.HandlerSymbol) {
			return false
		}
		switch row.Dispatch {
		case "static", "interface", "function_value", "builtin", "conversion", "unknown":
		default:
			return false
		}
		for _, refs := range [][]int{row.Args, row.Arguments} {
			for _, id := range refs {
				if !typeRef(id) {
					return false
				}
			}
		}
		if row.TargetSymbol != 0 && entry.Symbols[row.TargetSymbol-1].Package != row.TargetPackage {
			return false
		}
		if row.HandlerSymbol != 0 {
			handler := entry.Symbols[row.HandlerSymbol-1]
			if row.Dispatch != "static" || row.TargetPackage != "net/http" || row.TargetSymbol == 0 ||
				entry.Symbols[row.TargetSymbol-1].Name != "HandleFunc" ||
				entry.Symbols[row.TargetSymbol-1].Internal || len(row.Arguments) != 2 ||
				!handler.Internal || (handler.Kind != "function" && handler.Kind != "method") {
				return false
			}
		}
	}
	return true
}

func appendPackage(out *facts, entry packageCache, maxSites int) error {
	typeCount := len(out.Types) + len(entry.Types)
	symbolCount := len(out.Symbols) + len(entry.Symbols)
	siteCount := len(out.Sites) + len(entry.Sites)
	var exceeded []string
	if typeCount > maxTypes {
		exceeded = append(exceeded, "types")
	}
	if symbolCount > maxSymbols {
		exceeded = append(exceeded, "symbols")
	}
	if siteCount > maxSites {
		exceeded = append(exceeded, "sites")
	}
	if len(exceeded) != 0 {
		return fmt.Errorf("combined package facts budget exceeded: dimensions=%s; types=%d/%d, symbols=%d/%d, sites=%d/%d",
			strings.Join(exceeded, ","), typeCount, maxTypes, symbolCount, maxSymbols, siteCount, maxSites)
	}
	typeOffset, symbolOffset := len(out.Types), len(out.Symbols)
	ref := func(id, offset int) int {
		if id == 0 {
			return 0
		}
		return id + offset
	}
	refs := func(ids []int) []int {
		if ids == nil {
			return nil
		}
		out := make([]int, len(ids))
		for i, id := range ids {
			out[i] = ref(id, typeOffset)
		}
		return out
	}
	members := func(rows []memberFact) []memberFact {
		if rows == nil {
			return nil
		}
		out := append([]memberFact(nil), rows...)
		for i := range out {
			out[i].Type = ref(out[i].Type, typeOffset)
		}
		return out
	}
	out.Packages = append(out.Packages, entry.Package)
	for _, row := range entry.Types {
		row.ID += typeOffset
		row.OriginSymbol = ref(row.OriginSymbol, symbolOffset)
		row.Underlying, row.Elem = ref(row.Underlying, typeOffset), ref(row.Elem, typeOffset)
		row.Key, row.Receiver = ref(row.Key, typeOffset), ref(row.Receiver, typeOffset)
		row.Params, row.Returns = refs(row.Params), refs(row.Returns)
		row.TypeParams, row.Args, row.Embeds = refs(row.TypeParams), refs(row.Args), refs(row.Embeds)
		row.Fields, row.Methods = members(row.Fields), members(row.Methods)
		out.Types = append(out.Types, row)
	}
	for _, row := range entry.Symbols {
		row.ID += symbolOffset
		row.Type, row.Receiver = ref(row.Type, typeOffset), ref(row.Receiver, typeOffset)
		out.Symbols = append(out.Symbols, row)
	}
	for _, row := range entry.Sites {
		row.TargetSymbol = ref(row.TargetSymbol, symbolOffset)
		row.HandlerSymbol = ref(row.HandlerSymbol, symbolOffset)
		row.Type, row.Receiver = ref(row.Type, typeOffset), ref(row.Receiver, typeOffset)
		row.Args, row.Arguments = refs(row.Args), refs(row.Arguments)
		out.Sites = append(out.Sites, row)
	}
	return nil
}

func writePackageCache(dir string, entry packageCache, maxBytes int) error {
	data, err := json.Marshal(entry)
	if err != nil || len(data) > maxBytes {
		return errors.New("package cache byte budget exceeded")
	}
	return writePackageBytes(dir, entry.Key, data)
}

func writePackageBytes(dir, key string, data []byte) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".tmp-go-facts-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, "package-"+key+".json"))
}

func indexFragment(opts options, row *indexPackage, entry packageCache, referenced *int) (bool, error) {
	// Re-encode reused entries too: fragment byte hashes use the canonical cache encoding.
	data, err := json.Marshal(entry)
	if err != nil {
		return false, err
	}
	if len(data) > opts.MaxBytes {
		row.Status, row.Reason = "budget", "package cache byte budget exceeded"
		return false, nil
	}
	if len(data) > opts.MaxBytes-*referenced {
		row.Status, row.Reason = "unprocessed", "referenced fragment byte budget exceeded"
		return true, nil
	}
	if err := writePackageBytes(opts.Cache, entry.Key, data); err != nil {
		return false, err
	}
	*referenced += len(data)
	row.Status, row.Reason = "complete", ""
	row.Fragment = &fragmentDescriptor{
		File: "package-" + entry.Key + ".json", SHA256: digest(data), ByteLength: len(data),
		Types: len(entry.Types), Symbols: len(entry.Symbols), Sites: len(entry.Sites),
	}
	return false, nil
}

func (index *packageIndex) summarize() {
	index.Summary = map[string]int{
		"manifest_files": len(index.Files), "selected_packages": len(index.Packages),
	}
	statuses := make(map[string]string, len(index.Packages))
	for _, pkg := range index.Packages {
		statuses[pkg.ID] = pkg.Status
		switch pkg.Status {
		case "complete":
			index.Summary["complete_packages"]++
		case "unprocessed":
			index.Summary["unprocessed_packages"]++
		default:
			index.Summary["failed_packages"]++
		}
	}
	for _, file := range index.Files {
		if file.Selection != "selected" {
			index.Summary["not_selected_files"]++
			continue
		}
		index.Summary["selected_files"]++
		eligible := len(file.PackageIDs) != 0
		for _, id := range file.PackageIDs {
			eligible = eligible && statuses[id] == "complete"
		}
		if eligible {
			index.Summary["authoritative_files"]++
		} else {
			index.Summary["variant_blocked_files"]++
		}
	}
}

type chunkEncodingBuffer struct {
	bytes.Buffer
	budget *chunkBudgets
}

func (b *chunkEncodingBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := b.budget.MaxEncodedBytes - b.budget.EncodedBytes; n > remaining {
		n = remaining
	}
	if n > 0 {
		b.Buffer.Write(p[:n])
		b.budget.EncodedBytes += n
	}
	if n != len(p) {
		return n, errors.New("chunk wire encoding budget exceeded")
	}
	return n, nil
}

func chunkMarshal(entry packageCache, budget *chunkBudgets) ([]byte, error) {
	buffer := &chunkEncodingBuffer{budget: budget}
	if err := json.NewEncoder(buffer).Encode(entry); err != nil {
		return nil, err
	}
	data := buffer.Bytes()
	return data[:len(data)-1], nil
}

func chunkWire(entry packageCache, budget *chunkBudgets) ([]byte, error) {
	key, helper := entry.Key, entry.HelperSHA256
	for _, hash := range []string{key, helper} {
		if len(hash) != sha256.Size*2 || strings.Trim(hash, "0123456789abcdef") != "" {
			return nil, errors.New("invalid chunk key or helper hash")
		}
	}
	entry.Key, entry.HelperSHA256, entry.PayloadSHA256 = "", "", ""
	data, err := chunkMarshal(entry, budget)
	if err != nil {
		return nil, err
	}
	const prefix = "{\"Key\":\"\",\"HelperSHA256\":\"\",\"PayloadSHA256\":\"\""
	if !bytes.HasPrefix(data, []byte(prefix+",")) {
		return nil, errors.New("chunk canonical cache header differs")
	}
	payload := digest(data)
	header := []byte("{\"Key\":\"" + key + "\",\"HelperSHA256\":\"" + helper +
		"\",\"PayloadSHA256\":\"" + payload + "\"")
	extra := len(header) - len(prefix)
	if extra > budget.MaxEncodedBytes-budget.EncodedBytes {
		return nil, errors.New("chunk wire encoding budget exceeded")
	}
	budget.EncodedBytes += extra
	wire := make([]byte, len(data)+extra)
	copy(wire, header)
	copy(wire[len(header):], data[len(prefix):])
	return wire, nil
}

func chunkGroups(files []indexFile) []chunkFact {
	grouped := make(map[string]*chunkFact)
	var groups []chunkFact
	for _, file := range files {
		if file.Selection != "selected" {
			continue
		}
		key := digestJSON(file.PackageIDs)
		group := grouped[key]
		if group == nil {
			group = &chunkFact{PackageIDs: file.PackageIDs, Fragments: []chunkFragment{}}
			grouped[key] = group
		}
		group.Files = append(group.Files, file.Path)
	}
	for _, group := range grouped {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Files[0] < groups[j].Files[0] })
	return groups
}

type chunkWriter struct {
	opts       options
	out        *facts
	loader     *loader
	packages   map[string]*indexPackage
	compressor *gzip.Writer
	stopReason string
}

func (w *chunkWriter) key(group chunkFact) string {
	profile := "chunk_index_v1"
	if w.opts.ChunkIndexV2 {
		profile = "chunk_index_v2"
	}
	files := make([]fileFact, len(group.Files))
	packages := make(map[string]string, len(group.PackageIDs))
	for i, path := range group.Files {
		source := w.loader.manifest[filepath.Join(w.loader.root, filepath.FromSlash(path))]
		files[i] = fileFact{path, source.SHA256}
	}
	for _, id := range group.PackageIDs {
		packages[id] = w.out.Cache.PackageKeys[id]
	}
	return digestJSON(struct {
		Profile, HelperSHA256 string
		MaxSites, MaxBytes    int
		Files                 []fileFact
		Packages              map[string]string
	}{profile, w.out.Context.HelperSHA256, w.opts.MaxSites, w.opts.MaxBytes, files, packages})
}

func writeChunkBytes(directory, name string, data []byte) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".tmp-go-chunk-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(directory, name))
}

func (w *chunkWriter) attempt(group *chunkFact) (bool, error) {
	budget := w.out.Index.Budgets
	if err := w.loader.ctx.Err(); err != nil {
		w.stopReason = err.Error()
	}
	if budget.ExportAttempts >= budget.MaxExportAttempts {
		w.stopReason = "chunk export attempt budget exceeded"
	}
	if w.stopReason != "" {
		group.Status, group.Reason = "unprocessed", w.stopReason
		return false, nil
	}
	budget.ExportAttempts++
	admitted := make(map[string]bool, len(group.Files))
	for _, path := range group.Files {
		admitted[path] = true
	}
	packages := make([]*checkedPackage, len(group.PackageIDs))
	for i, id := range group.PackageIDs {
		pkg := w.loader.check(id)
		packages[i] = pkg
		w.packages[id].packageFact = pkg.Fact
		if err := w.loader.ctx.Err(); err != nil {
			w.stopReason = err.Error()
			group.Status, group.Reason = "unprocessed", w.stopReason
			return false, nil
		}
	}
	for _, pkg := range packages {
		if pkg.Fact.IllTyped {
			group.Status, group.Reason = "ill_typed", "package_type_errors: "+pkg.Fact.ID
			return false, nil
		}
	}
	var compressed [][]byte
	rawBytes, compressedBytes, sites := 0, 0, 0
	var fragments []chunkFragment
	for i, id := range group.PackageIDs {
		local := facts{}
		g := &exporter{loader: w.loader, out: &local, typeIDs: make(map[types.Type]int),
			symIDs: make(map[types.Object]int)}
		seen := make(map[string]bool, len(group.Files))
		for _, name := range packages[i].Meta.CgoFiles {
			if source := w.loader.manifest[filepath.Join(packages[i].Meta.Dir, name)]; source != nil && admitted[source.Path] {
				seen[source.Path] = true
			}
		}
		for _, file := range packages[i].Files {
			source := w.loader.exportSource(packages[i], file)
			if source == nil || !admitted[source.Path] {
				continue
			}
			seen[source.Path] = true
			g.exportFile(packages[i], file, source, w.opts.MaxSites)
			if g.err != nil {
				break
			}
		}
		if err := w.loader.ctx.Err(); err != nil {
			w.stopReason = err.Error()
			group.Status, group.Reason = "unprocessed", w.stopReason
			return false, nil
		}
		if g.err != nil {
			group.Status, group.Reason = "budget", g.err.Error()
			return true, nil
		}
		if len(seen) != len(admitted) {
			return false, fmt.Errorf("chunk package source membership differs: %s", id)
		}
		entry := packageCache{Key: w.out.Cache.PackageKeys[id], HelperSHA256: w.out.Context.HelperSHA256,
			Package: packages[i].Fact,
			Types:   local.Types, Symbols: local.Symbols, Sites: local.Sites}
		if !validPackageContent(entry, w.loader, w.loader.listed[id], entry.Key,
			entry.HelperSHA256, w.opts.MaxSites) {
			return false, fmt.Errorf("constructed chunk facts failed validation: %s", id)
		}
		var data []byte
		var err error
		if w.opts.ChunkIndexV2 {
			data, err = compactWire(entry, budget)
		} else {
			data, err = chunkWire(entry, budget)
		}
		if err != nil {
			w.stopReason = err.Error()
			group.Status, group.Reason = "unprocessed", w.stopReason
			return false, nil
		}
		rawBytes += len(data)
		sites += len(entry.Sites)
		if rawBytes > budget.MaxChunkRawBytes || sites > budget.MaxChunkSites {
			group.Status, group.Reason = "budget", "chunk raw byte or site budget exceeded"
			return true, nil
		}
		buffer := &limitedBuffer{limit: w.opts.MaxBytes - compressedBytes}
		if w.compressor == nil {
			w.compressor = gzip.NewWriter(buffer)
		} else {
			w.compressor.Reset(buffer)
		}
		writer := w.compressor
		if _, err := writer.Write(data); err != nil {
			writer.Close()
			group.Status, group.Reason = "budget", "chunk compressed byte budget exceeded"
			return true, nil
		}
		if err := writer.Close(); err != nil {
			group.Status, group.Reason = "budget", "chunk compressed byte budget exceeded"
			return true, nil
		}
		encoded := buffer.Bytes()
		compressedBytes += len(encoded)
		compressed = append(compressed, encoded)
		fragments = append(fragments, chunkFragment{
			PackageID: id, Key: entry.Key, File: "chunk-" + digest([]byte(group.Key+":"+entry.Key)) + ".json.gz",
			SHA256: digest(encoded), ByteLength: len(encoded), RawSHA256: digest(data),
			RawByteLength: len(data), Types: len(entry.Types), Symbols: len(entry.Symbols), Sites: len(entry.Sites),
		})
	}
	if compressedBytes > budget.MaxReferencedCompressedBytes-budget.ReferencedCompressedBytes ||
		rawBytes > budget.MaxExpandedBytes-budget.ExpandedBytes {
		w.stopReason = "chunk cumulative compressed or expanded byte budget exceeded"
		group.Status, group.Reason = "unprocessed", w.stopReason
		return false, nil
	}
	if err := w.loader.ctx.Err(); err != nil {
		w.stopReason = err.Error()
		group.Status, group.Reason = "unprocessed", w.stopReason
		return false, nil
	}
	// Reserve the complete group before writing; failed writes cannot admit later chunks.
	budget.ReferencedCompressedBytes += compressedBytes
	budget.ExpandedBytes += rawBytes
	for i, fragment := range fragments {
		if err := writeChunkBytes(w.opts.Cache, fragment.File, compressed[i]); err != nil {
			return false, err
		}
	}
	group.Status, group.Reason, group.Fragments = "complete", "", fragments
	return false, nil
}

func (w *chunkWriter) emit(group chunkFact) error {
	group.Key, group.Fragments = w.key(group), []chunkFragment{}
	split, err := w.attempt(&group)
	if err != nil {
		return err
	}
	if split && len(group.Files) > 1 {
		middle := len(group.Files) / 2
		if err := w.emit(chunkFact{Files: group.Files[:middle], PackageIDs: group.PackageIDs}); err != nil {
			return err
		}
		return w.emit(chunkFact{Files: group.Files[middle:], PackageIDs: group.PackageIDs})
	}
	w.out.Index.Chunks = append(w.out.Index.Chunks, group)
	return nil
}

func exportChunks(out *facts, l *loader, opts options) error {
	writer := &chunkWriter{opts: opts, out: out, loader: l, packages: make(map[string]*indexPackage)}
	remaining := make(map[string]int)
	groups := chunkGroups(out.Index.Files)
	for i := range out.Index.Packages {
		row := &out.Index.Packages[i]
		writer.packages[row.ID] = row
	}
	for _, group := range groups {
		for _, id := range group.PackageIDs {
			remaining[id]++
		}
		out.Index.Budgets.MaxExportAttempts += 2 * len(group.Files)
	}
	for _, group := range groups {
		if err := writer.emit(group); err != nil {
			return err
		}
		for _, id := range group.PackageIDs {
			remaining[id]--
			if remaining[id] == 0 {
				l.discardSyntax(id)
			}
		}
	}
	for i := range out.Index.Packages {
		row := &out.Index.Packages[i]
		row.Status, row.Reason = "complete", ""
	}
	for _, chunk := range out.Index.Chunks {
		if chunk.Status == "complete" {
			continue
		}
		for _, id := range chunk.PackageIDs {
			row := writer.packages[id]
			if row.Status == "complete" || chunk.Status == "ill_typed" ||
				(chunk.Status == "budget" && row.Status == "unprocessed") {
				row.Status, row.Reason = chunk.Status, chunk.Reason
			}
		}
	}
	for _, row := range out.Index.Packages {
		if row.Status == "complete" {
			out.Cache.Rebuilt = append(out.Cache.Rebuilt, row.ID)
		}
	}
	return nil
}

func goBuildContext(ctx context.Context, root string, opts options, build *contextFact) error {
	envData, err := runGo(ctx, root, opts, "env", "-json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(envData, &build.Env); err != nil {
		return err
	}
	// This derived value embeds a fresh temporary directory.
	delete(build.Env, "GOGCCFLAGS")
	build.ToolVersion = build.Env["GOVERSION"]
	build.CGOPolicy = "disabled-for-pilot"
	if opts.Cgo {
		if build.Env["CGO_ENABLED"] != "1" || build.Env["GOOS"] != runtime.GOOS ||
			build.Env["GOARCH"] != runtime.GOARCH {
			return errors.New("cgo facts require a native Go build profile")
		}
		build.CGOPolicy = "explicit-native"
	}
	if build.ToolVersion != runtime.Version() {
		return fmt.Errorf("helper %s and toolchain %s must match", runtime.Version(), build.ToolVersion)
	}
	build.BuildFlags, err = buildFlags(build.Env)
	return err
}

func goPackageList(ctx context.Context, root string, opts options, flags []string, jsonFlag string) ([]byte, error) {
	args := append([]string{"list", "-deps", "-e", "-export", "-compiled", "-test", jsonFlag}, flags...)
	// Cap cold compiler fan-out on Windows, where the Job charges commit for the entire tree.
	if runtime.GOOS == "windows" && runtime.GOMAXPROCS(0) > 8 &&
		!slices.ContainsFunc(flags, func(flag string) bool { return strings.HasPrefix(flag, "-p=") }) {
		args = append(args, "-p=8")
	}
	return runGo(ctx, root, opts, append(args, opts.Patterns...)...)
}

func prewarm(ctx context.Context, opts options) (int, error) {
	if excludedTree(opts.Root) {
		return 0, errors.New("discovery root is inside an excluded temporary rebase tree")
	}
	root, err := canonical(opts.Root)
	if err != nil {
		return 0, err
	}
	if excludedTree(root) {
		return 0, errors.New("discovery root is inside an excluded temporary rebase tree")
	}
	var build contextFact
	if err := goBuildContext(ctx, root, opts, &build); err != nil {
		return 0, err
	}
	data, err := goPackageList(ctx, root, opts, build.BuildFlags, "-json=ImportPath,Error,DepsErrors")
	if err != nil {
		return 0, err
	}
	seen := make(map[string]bool)
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg listPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return 0, err
		}
		if pkg.ImportPath == "" || seen[pkg.ImportPath] {
			return 0, errors.New("invalid or duplicate Go package inventory")
		}
		if pkg.Error != nil || len(pkg.DepsErrors) != 0 {
			detail := pkg.Error
			if detail == nil {
				detail = &pkg.DepsErrors[0]
			}
			return 0, fmt.Errorf("Go package %s: %.512s", pkg.ImportPath, strings.TrimSpace(detail.Err))
		}
		seen[pkg.ImportPath] = true
	}
	if len(seen) == 0 {
		return 0, errors.New("Go package inventory is empty")
	}
	return len(seen), ctx.Err()
}

func analyze(ctx context.Context, opts options) (out facts, err error) {
	out = initialFacts(opts)
	if err := validateOptions(opts); err != nil {
		return out, err
	}
	if excludedTree(opts.Root) {
		return out, errors.New("discovery root is inside an excluded temporary rebase tree")
	}
	out.Root, err = canonical(opts.Root)
	if err != nil {
		return out, err
	}
	cgoHeaders := opts.Cgo && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && (opts.PackageIndex || opts.ChunkIndex || opts.ChunkIndexV2)
	manifest, files, err := readManifest(ctx, out.Root, opts.Manifest, cgoHeaders)
	if err != nil {
		return out, err
	}
	out.Files, out.Context.Patterns = files, opts.Patterns
	out.Context.ManifestSHA256 = digestJSON(files)
	executable, err := os.Executable()
	if err != nil {
		return out, err
	}
	out.Context.HelperSHA256, err = digestFile(executable)
	if err != nil {
		return out, err
	}
	command, err := exec.LookPath(opts.Go)
	if err != nil {
		return out, err
	}
	out.Context.ToolSHA256, err = digestFile(command)
	if err != nil {
		return out, err
	}
	if err := goBuildContext(ctx, out.Root, opts, &out.Context); err != nil {
		return out, err
	}
	configs := make(map[string]string)
	configPaths := []string{out.Context.Env["GOMOD"], out.Context.Env["GOWORK"], out.Context.Env["GOENV"]}
	for _, flag := range out.Context.BuildFlags {
		if strings.HasPrefix(flag, "-modfile=") {
			configPaths = append(configPaths, strings.TrimPrefix(flag, "-modfile="))
		}
	}
	for _, path := range configPaths {
		if err := addConfig(configs, path); err != nil {
			return out, err
		}
		sumPath := ""
		if strings.HasSuffix(path, ".mod") {
			sumPath = strings.TrimSuffix(path, ".mod") + ".sum"
		} else if strings.HasSuffix(path, ".work") {
			sumPath = path + ".sum"
		}
		if sumPath != "" {
			if err := addConfig(configs, sumPath); err != nil {
				return out, err
			}
			if err := addConfig(configs, filepath.Join(filepath.Dir(path), "vendor", "modules.txt")); err != nil {
				return out, err
			}
		}
	}
	listData, err := goPackageList(ctx, out.Root, opts, out.Context.BuildFlags,
		"-json=ImportPath,Name,Dir,ForTest,Export,Standard,GoFiles,CgoFiles,HFiles,MFiles,CompiledGoFiles,InvalidGoFiles,Imports,ImportMap,Module,Error,DepsErrors")
	if err != nil {
		return out, err
	}
	l := &loader{ctx: ctx, root: out.Root, fset: token.NewFileSet(),
		listed: make(map[string]*listPackage), checked: make(map[string]*checkedPackage),
		loading: make(map[string]bool), sources: make(map[string]*sourceFile), manifest: manifest,
		locations: make(map[types.Object]*location), pkgIDs: make(map[*types.Package]string),
		identities: map[string]string{opts.Root: out.Root}, exportDeps: make(map[string]bool),
		goarch: out.Context.Env["GOARCH"], sourceCount: len(manifest), strictImports: opts.PackageIndex || opts.ChunkIndex || opts.ChunkIndexV2,
		cgoHeaders: cgoHeaders}
	for _, source := range manifest {
		l.sourceBytes += len(source.Data)
		if out.Index != nil {
			l.sources[source.Abs] = source
			l.identities[source.Abs] = source.Abs
		}
	}
	archivePaths := make(map[string]struct{})
	decoder := json.NewDecoder(bytes.NewReader(listData))
	for {
		var meta listPackage
		if err := decoder.Decode(&meta); err == io.EOF {
			break
		} else if err != nil {
			return out, err
		}
		if meta.ImportPath == "" || l.listed[meta.ImportPath] != nil {
			return out, errors.New("invalid or duplicate Go package inventory")
		}
		l.listed[meta.ImportPath] = &meta
		if meta.Export != "" {
			archivePaths[meta.Export] = struct{}{}
		}
	}
	exports, sources := make(map[string]string), make(map[string]string)
	exportFiles := make(map[string]string, len(archivePaths))
	var exportMu sync.Mutex
	if err := checkPaths(ctx, archivePaths, func(path string, _ struct{}) error {
		hash, err := digestFile(path)
		if err != nil {
			return err
		}
		exportMu.Lock()
		exportFiles[path] = hash
		exportMu.Unlock()
		return nil
	}); err != nil {
		return out, err
	}
	out.Cache.PackageFiles = make(map[string][]string)
	packageFileCount := 0
	var ownIDs []string
	inventoryErrorDirs := make(map[string]bool)
	unlocatedInventoryError := false
	for id, meta := range l.listed {
		for mod := meta.Module; mod != nil; mod = mod.Replace {
			for _, path := range []string{mod.GoMod, filepath.Join(mod.Dir, "go.sum"),
				filepath.Join(mod.Dir, "vendor", "modules.txt")} {
				if mod.Dir != "" {
					if err := addConfig(configs, path); err != nil {
						return out, err
					}
				}
			}
		}
		if meta.Export != "" {
			exports[id] = exportFiles[meta.Export]
		} else {
			exports[id] = "missing"
		}
		dir, dirErr := l.canonicalInput(meta.Dir)
		// go list -e can report a broken package with no admitted GoFiles.
		if out.Index != nil && (meta.Error != nil || len(meta.DepsErrors) != 0 ||
			len(meta.InvalidGoFiles) != 0) {
			if meta.Dir == "" || dirErr != nil {
				unlocatedInventoryError = true
			} else if _, own := within(out.Root, dir); own {
				inventoryErrorDirs[dir] = true
			}
		}
		if dirErr != nil {
			continue
		}
		if _, own := within(out.Root, dir); !own {
			continue
		}
		admitted := make(map[string]bool)
		paths := meta.CompiledGoFiles
		if len(paths) == 0 {
			paths = meta.GoFiles
		}
		for _, path := range slices.Concat(paths, meta.CgoFiles) {
			source, err := l.source(path, meta.Dir)
			if err != nil {
				return out, err
			}
			sources[source.Abs] = source.SHA256
			if manifest[source.Abs] != nil {
				admitted[source.Path] = true
			}
		}
		// A replacement can live inside the root while remaining a dependency.
		if len(admitted) == 0 && meta.Module != nil && meta.Module.Replace != nil &&
			meta.Export != "" && id == packagePath(id) {
			l.exportDeps[id] = true
		}
		if len(admitted) != 0 {
			ownIDs = append(ownIDs, id)
			for path := range admitted {
				out.Cache.PackageFiles[id] = append(out.Cache.PackageFiles[id], path)
			}
			sort.Strings(out.Cache.PackageFiles[id])
			packageFileCount += len(admitted)
			if len(ownIDs) > maxSourceFiles || packageFileCount > maxPackageFiles {
				return out, errors.New("package file membership budget exceeded")
			}
		}
	}
	out.Context.ConfigSHA256, out.Context.ExportsSHA256 = digestJSON(configs), digestJSON(exports)
	out.Context.SourceSHA256 = digestJSON(sources)
	out.Context.DependenciesSHA256 = digestJSON(struct{ Configs, Exports map[string]string }{configs, exports})
	out.Cache.Key = digestJSON(struct {
		Schema, MaxSites int
		Version, Root    string
		Context          contextFact
	}{out.Schema, opts.MaxSites, out.HelperVersion, out.Root, out.Context})
	if opts.ChunkIndexV2 {
		out.Cache.Key = compactContextKey(out, out.Cache.Key)
	}
	if err := snapshotUnchanged(ctx, l.sources); err != nil {
		return out, err
	}
	if err := identitiesUnchanged(ctx, l.identities); err != nil {
		return out, err
	}
	if err := inputsUnchanged(ctx, configs); err != nil {
		return out, err
	}
	if err := inputsUnchanged(ctx, exportFiles); err != nil {
		return out, err
	}
	base := out.Context
	base.ManifestSHA256, base.SourceSHA256, base.ExportsSHA256, base.DependenciesSHA256 = "", "", "", ""
	keyBase := digestJSON(struct {
		Schema  int
		Root    string
		Context contextFact
	}{out.Schema, out.Root, base})
	if opts.ChunkIndexV2 {
		keyBase = compactContextKey(out, keyBase)
	}
	keys := packageKeys(l, keyBase, exports)
	out.Cache.PackageKeys = make(map[string]string, len(ownIDs))
	for _, id := range ownIDs {
		out.Cache.PackageKeys[id] = keys[id]
		if out.Index != nil && keys[id] == "" {
			// Failed packages still need snapshot-sensitive diagnostic/invalidation keys.
			out.Cache.PackageKeys[id] = digestJSON(struct {
				Context contextFact
				Package *listPackage
			}{out.Context, l.listed[id]})
			if opts.ChunkIndexV2 {
				out.Cache.PackageKeys[id] = compactContextKey(out, out.Cache.PackageKeys[id])
			}
		}
	}
	l.gc = importer.ForCompiler(l.fset, "gc", func(path string) (io.ReadCloser, error) {
		meta := l.listed[path]
		if meta == nil || meta.Export == "" {
			return nil, fmt.Errorf("no export data for dependency %s", path)
		}
		return os.Open(meta.Export)
	})
	sort.Strings(ownIDs)
	if out.Index != nil {
		members := make(map[string][]string)
		for _, id := range ownIDs {
			meta := l.listed[id]
			out.Index.Packages = append(out.Index.Packages, indexPackage{
				packageFact: packageFact{ID: id, Path: packagePath(id), Dir: filepath.ToSlash(meta.Dir),
					Name: meta.Name, ForTest: meta.ForTest},
				ForTest: meta.ForTest, Status: "unprocessed", Key: out.Cache.PackageKeys[id],
				Files: out.Cache.PackageFiles[id], Reason: "not_processed",
			})
			for _, path := range out.Cache.PackageFiles[id] {
				members[path] = append(members[path], id)
			}
		}
		for _, file := range out.Files {
			source := manifest[filepath.Join(out.Root, filepath.FromSlash(file.Path))]
			row := indexFile{fileFact: file, ByteLength: len(source.Data),
				Selection: "selected", PackageIDs: members[file.Path]}
			if len(row.PackageIDs) == 0 {
				row.Selection, row.Reason = "not_selected", "not_selected_by_go_list"
				row.PackageIDs = []string{}
				row.SelectionVerified = strings.HasSuffix(file.Path, ".go") &&
					!unlocatedInventoryError && !inventoryErrorDirs[filepath.Dir(source.Abs)]
			}
			out.Index.Files = append(out.Index.Files, row)
		}
		out.Index.InventoryComplete = true
	}
	var pending []packageCache
	referenced, stopReason := 0, ""
	exportIDs := ownIDs
	if opts.ChunkIndex || opts.ChunkIndexV2 {
		if err := exportChunks(&out, l, opts); err != nil {
			return out, err
		}
		exportIDs = nil
	}
	for position, id := range exportIDs {
		if out.Index != nil && position > 0 {
			// Imports may have checked later packages before their own export turn.
			l.discardSyntax(ownIDs[position-1])
		}
		key := out.Cache.PackageKeys[id]
		var indexRow *indexPackage
		if out.Index != nil {
			indexRow = &out.Index.Packages[position]
			if ctx.Err() != nil {
				stopReason = ctx.Err().Error()
			}
			if stopReason != "" {
				indexRow.Reason = stopReason
				continue
			}
		}
		var cached packageCache
		if opts.Cache != "" && key != "" && (indexRow == nil || keys[id] != "") {
			data, readErr := readLimited(filepath.Join(opts.Cache, "package-"+key+".json"), int64(opts.MaxBytes))
			if readErr == nil && json.Unmarshal(data, &cached) == nil &&
				validPackageCache(cached, l, l.listed[id], key, out.Context.HelperSHA256, opts.MaxSites) {
				if indexRow != nil {
					stop, err := indexFragment(opts, indexRow, cached, &referenced)
					if err != nil {
						return out, err
					}
					if stop {
						stopReason = indexRow.Reason
					}
					if indexRow.Status != "complete" {
						continue
					}
				} else if err := appendPackage(&out, cached, opts.MaxSites); err != nil {
					return out, err
				}
				out.Cache.Reused = append(out.Cache.Reused, id)
				continue
			}
		}
		pkg := l.check(id)
		if indexRow != nil {
			indexRow.packageFact = pkg.Fact
			if ctx.Err() != nil {
				indexRow.Reason = ctx.Err().Error()
				stopReason = indexRow.Reason
				continue
			}
			if pkg.Fact.IllTyped {
				indexRow.Status, indexRow.Reason = "ill_typed", "package_type_errors"
				continue
			}
		}
		local := facts{}
		g := &exporter{loader: l, out: &local, typeIDs: make(map[types.Type]int), symIDs: make(map[types.Object]int)}
		for _, file := range pkg.Files {
			source := l.exportSource(pkg, file)
			if source == nil || manifest[source.Abs] == nil {
				continue
			}
			g.exportFile(pkg, file, source, opts.MaxSites)
		}
		if g.err != nil {
			if indexRow != nil {
				indexRow.Status, indexRow.Reason = "budget", g.err.Error()
				continue
			}
			return out, g.err
		}
		if indexRow != nil && ctx.Err() != nil {
			indexRow.Reason = ctx.Err().Error()
			stopReason = indexRow.Reason
			continue
		}
		entry := packageCache{Key: key, HelperSHA256: out.Context.HelperSHA256,
			Package: pkg.Fact, Types: local.Types, Symbols: local.Symbols, Sites: local.Sites}
		entry.PayloadSHA256 = entry.payloadHash()
		if indexRow != nil {
			if !validPackageCache(entry, l, l.listed[id], key, out.Context.HelperSHA256, opts.MaxSites) {
				return out, fmt.Errorf("constructed package facts failed validation: %s", id)
			}
			stop, err := indexFragment(opts, indexRow, entry, &referenced)
			if err != nil {
				return out, err
			}
			if stop {
				stopReason = indexRow.Reason
			}
			if indexRow.Status == "complete" {
				out.Cache.Rebuilt = append(out.Cache.Rebuilt, id)
			}
			continue
		}
		if err := appendPackage(&out, entry, opts.MaxSites); err != nil {
			return out, err
		}
		out.Cache.Rebuilt = append(out.Cache.Rebuilt, id)
		if key != "" && !pkg.Fact.IllTyped {
			pending = append(pending, entry)
		}
	}
	for id := range l.checked {
		out.Cache.Checked = append(out.Cache.Checked, id)
	}
	sort.Strings(out.Cache.Checked)
	if ctx.Err() != nil && out.Index == nil {
		return out, ctx.Err()
	}
	if len(ownIDs) == 0 {
		return out, errors.New("package selection contains no manifest-admitted Go sources")
	}
	if err := snapshotUnchanged(ctx, l.sources); err != nil {
		return out, err
	}
	if err := identitiesUnchanged(ctx, l.identities); err != nil {
		return out, err
	}
	if err := inputsUnchanged(ctx, configs); err != nil {
		return out, err
	}
	if err := inputsUnchanged(ctx, exportFiles); err != nil {
		return out, err
	}
	if out.Index != nil {
		out.Index.InputSnapshotStable = true
		out.Index.summarize()
		out.Status, out.Complete = "ok", true
		for _, pkg := range out.Index.Packages {
			if pkg.Status != "complete" {
				out.Status, out.Complete = "partial", false
			}
		}
		out.Cache.Hit = !opts.ChunkIndex && !opts.ChunkIndexV2 && out.Complete && len(out.Cache.Reused) == len(ownIDs)
		return out, nil
	}
	out.Status, out.Complete = "ok", true
	for _, pkg := range out.Packages {
		if pkg.IllTyped {
			out.Status, out.Complete = "degraded", false
		}
	}
	out.Cache.Hit = out.Complete && len(out.Cache.Reused) == len(ownIDs)
	if opts.Cache != "" && out.Complete {
		data, err := json.Marshal(out)
		if err != nil || len(data) > opts.MaxBytes {
			return out, errors.New("JSON output budget exceeded")
		}
		for _, entry := range pending {
			if err := writePackageCache(opts.Cache, entry, opts.MaxBytes); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func fail(out facts, err error) facts {
	out.Status, out.Complete = "degraded", false
	if out.Index != nil {
		out.Status = "partial"
		out.Index.InputSnapshotStable = false
		for i := range out.Index.Packages {
			row := &out.Index.Packages[i]
			if row.Fragment != nil || ((out.Schema == 3 || out.Schema == 4) && row.Status == "complete") {
				row.Status, row.Reason = "unprocessed", "input_snapshot_not_validated"
				row.Fragment = nil
			}
		}
		for i := range out.Index.Chunks {
			chunk := &out.Index.Chunks[i]
			chunk.Status, chunk.Reason = "unprocessed", "input_snapshot_not_validated"
			chunk.Fragments = []chunkFragment{}
		}
		if out.Index.Budgets != nil {
			out.Index.Budgets.ReferencedCompressedBytes, out.Index.Budgets.ExpandedBytes = 0, 0
		}
		out.Index.summarize()
	}
	out.Types, out.Symbols, out.Sites = nil, nil, nil
	out.Errors = append(out.Errors, err.Error())
	return out
}

func main() {
	var opts options
	var patterns string
	flag.StringVar(&opts.Root, "root", ".", "explicit discovery root")
	flag.StringVar(&opts.Manifest, "manifest", "", "discovery path/SHA-256 manifest")
	flag.StringVar(&opts.Cache, "cache", "", "optional content-keyed cache directory")
	flag.BoolVar(&opts.PackageIndex, "package-index", false, "emit a partial package index (requires --cache)")
	flag.BoolVar(&opts.ChunkIndex, "chunk-index", false, "emit a bounded chunk index (requires --cache)")
	flag.BoolVar(&opts.ChunkIndexV2, "chunk-index-v2", false, "emit a compact bounded chunk index (requires --cache)")
	opts.Cgo = os.Getenv("CBM_GO_FACTS_CGO") == "1"
	prewarmOnly := flag.Bool("prewarm", false, "populate the Go build cache without publishing facts")
	goCommand := os.Getenv("CBM_GO_COMMAND")
	if goCommand == "" {
		goCommand = "go"
	}
	flag.StringVar(&opts.Go, "go", goCommand, "Go command matching the helper toolchain")
	flag.StringVar(&patterns, "packages", "./...", "comma-separated Go package patterns")
	flag.IntVar(&opts.BudgetMS, "budget-ms", 60000, "whole-run wall-clock budget")
	flag.IntVar(&opts.MaxSites, "max-sites", 100000, "maximum emitted call sites")
	flag.IntVar(&opts.MaxBytes, "max-bytes", 32<<20, "maximum emitted JSON bytes")
	flag.Parse()
	opts.Patterns = strings.Split(patterns, ",")
	if *prewarmOnly {
		err := validateOptions(opts)
		if err == nil && (opts.Manifest != "" || opts.Cache != "" || opts.PackageIndex ||
			opts.ChunkIndex || opts.ChunkIndexV2) {
			err = errors.New("--prewarm cannot be combined with manifest or fact cache options")
		}
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.BudgetMS)*time.Millisecond)
			count, prewarmErr := prewarm(ctx, opts)
			cancel()
			if prewarmErr == nil {
				fmt.Printf("{\"packages\":%d}\n", count)
				return
			}
			err = prewarmErr
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := validateOptions(opts); err != nil {
		data, _ := json.Marshal(fail(initialFacts(opts), err))
		os.Stdout.Write(append(data, '\n'))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.BudgetMS)*time.Millisecond)
	defer cancel()
	result := make(chan facts, 1)
	go func() {
		out, err := analyze(ctx, opts)
		if err != nil {
			out = fail(out, err)
		}
		result <- out
	}()
	var out facts
	select {
	case out = <-result:
	case <-ctx.Done():
		out = fail(initialFacts(opts), ctx.Err())
	}
	data, err := json.Marshal(out)
	if err != nil || len(data) > opts.MaxBytes {
		out = fail(initialFacts(opts),
			errors.New("JSON output budget exceeded"))
		data, _ = json.Marshal(out)
	}
	os.Stdout.Write(append(data, '\n'))
}
