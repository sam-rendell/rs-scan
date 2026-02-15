package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"

	"rs_scan/internal/enrich"
)

func main() {
	var (
		inputFile   string
		outputFile  string
		recogDir    string
		nucleiDir   string
		verbose     bool
		passThrough bool
		cpuprofile  string
		workers     int
	)

	flag.StringVar(&inputFile, "i", "", "input JSONL file (default stdin)")
	flag.StringVar(&outputFile, "o", "", "output JSONL file (default stdout)")
	flag.StringVar(&recogDir, "r", "", "recog XML directory")
	flag.StringVar(&nucleiDir, "n", "", "nuclei templates directory")
	flag.BoolVar(&verbose, "v", false, "verbose: log match stats to stderr")
	flag.BoolVar(&passThrough, "pass-through", true, "pass OPEN/TIMEOUT events unchanged")
	flag.StringVar(&cpuprofile, "cpuprofile", "", "write CPU profile to file")
	flag.IntVar(&workers, "w", runtime.NumCPU(), "number of parallel workers")
	flag.Parse()

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cpuprofile: %v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if recogDir == "" && nucleiDir == "" {
		fmt.Fprintln(os.Stderr, "error: at least one of -r (recog) or -n (nuclei) must be specified")
		os.Exit(1)
	}

	// Load sources
	var recogDBs map[string]*enrich.FingerprintDB
	var nucleiTemplates []*enrich.NucleiTemplate

	if recogDir != "" {
		var err error
		recogDBs, err = enrich.LoadRecogDir(recogDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading recog: %v\n", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "loaded %d recog databases (%d fingerprints)\n",
				len(recogDBs), enrich.RecogDBCount(recogDBs))
		}
	}

	if nucleiDir != "" {
		var err error
		nucleiTemplates, err = enrich.LoadNucleiDir(nucleiDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading nuclei: %v\n", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "loaded %d nuclei templates\n", len(nucleiTemplates))
		}
	}

	router := enrich.NewRouter(recogDBs, nucleiTemplates)

	// Open I/O
	var reader io.Reader = os.Stdin
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening input: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	}

	var writer io.Writer = os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}

	// Stats (atomic for concurrent workers)
	var total, banners, matched, unmatched, recogHit, nucleiHit atomic.Int64

	// Buffered writer for output
	bw := bufio.NewWriterSize(writer, 256*1024)
	defer bw.Flush()

	var outMu sync.Mutex

	// writeJSON writes a JSON-encoded line to output, mutex-protected.
	writeJSON := func(record map[string]any) {
		data, err := json.Marshal(record)
		if err != nil {
			return
		}
		outMu.Lock()
		bw.Write(data)
		bw.WriteByte('\n')
		outMu.Unlock()
	}

	// writeRaw writes a raw line to output.
	writeRaw := func(line string) {
		outMu.Lock()
		bw.WriteString(line)
		bw.WriteByte('\n')
		outMu.Unlock()
	}

	if workers < 1 {
		workers = 1
	}

	// Work channel
	type workItem struct {
		line []byte
	}
	work := make(chan workItem, workers*64)

	var wg sync.WaitGroup

	// Start workers
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range work {
				total.Add(1)

				var record map[string]any
				if err := json.Unmarshal(item.line, &record); err != nil {
					writeRaw(string(item.line))
					continue
				}

				event, _ := record["event"].(string)

				if event != "BANNER" {
					if passThrough {
						writeJSON(record)
					}
					continue
				}

				banners.Add(1)

				banner, _ := record["banner"].(string)
				portFloat, _ := record["port"].(float64)
				port := uint16(portFloat)
				proto, _ := record["proto"].(string)

				result := router.Enrich(banner, port, proto)
				if result == nil {
					unmatched.Add(1)
					writeJSON(record)
					continue
				}

				matched.Add(1)

				if strings.HasPrefix(result.Source, "recog:") {
					recogHit.Add(1)
				}
				if len(result.NucleiIDs) > 0 {
					nucleiHit.Add(1)
				}

				setIfNonEmpty(record, "service_vendor", result.ServiceVendor)
				setIfNonEmpty(record, "service_product", result.ServiceProduct)
				setIfNonEmpty(record, "service_version", result.ServiceVersion)
				setIfNonEmpty(record, "service_cpe", result.ServiceCPE)
				setIfNonEmpty(record, "os_vendor", result.OSVendor)
				setIfNonEmpty(record, "os_product", result.OSProduct)
				setIfNonEmpty(record, "os_version", result.OSVersion)
				setIfNonEmpty(record, "os_family", result.OSFamily)
				setIfNonEmpty(record, "os_device", result.OSDevice)
				setIfNonEmpty(record, "hw_vendor", result.HWVendor)
				setIfNonEmpty(record, "hw_product", result.HWProduct)
				setIfNonEmpty(record, "description", result.Description)
				setIfNonEmpty(record, "matched_by", result.Source)

				if len(result.NucleiIDs) > 0 {
					record["nuclei_ids"] = result.NucleiIDs
				}

				writeJSON(record)
			}
		}()
	}

	// Read input and dispatch to workers
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Copy line since scanner reuses buffer
		cp := make([]byte, len(line))
		copy(cp, line)
		work <- workItem{line: cp}
	}
	close(work)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}

	bw.Flush()

	if verbose {
		fmt.Fprintf(os.Stderr, "---\n")
		fmt.Fprintf(os.Stderr, "total lines: %d\n", total.Load())
		fmt.Fprintf(os.Stderr, "banners:     %d\n", banners.Load())
		fmt.Fprintf(os.Stderr, "matched:     %d (%.1f%%)\n", matched.Load(), pct(matched.Load(), banners.Load()))
		fmt.Fprintf(os.Stderr, "unmatched:   %d\n", unmatched.Load())
		fmt.Fprintf(os.Stderr, "recog hits:  %d\n", recogHit.Load())
		fmt.Fprintf(os.Stderr, "nuclei hits: %d\n", nucleiHit.Load())
		fmt.Fprintf(os.Stderr, "workers:     %d\n", workers)
	}
}

func setIfNonEmpty(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
