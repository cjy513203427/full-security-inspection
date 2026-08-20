//go:build ignore

// One-off generator for the application icon embedded into the built exe
// (see cmd/netwatch/rsrc_windows_amd64.syso, produced from this file's
// output via go-winres — see README note at the bottom of this file). Run
// with:
//
//	go run tools/genappicon/main.go
//
// The shield silhouette is the exact path used for the "shield" icon in
// the web dashboard's SVG sprite (internal/web/static/index.html), so the
// exe icon, tray icon family, and in-app iconography all read as the same
// mark at different scales.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

type pt struct{ x, y float64 }

// cubicBezier samples a cubic Bezier curve from p0 (exclusive) to p3
// (inclusive) into `steps` points, so consecutive curve segments can be
// concatenated into one closed polygon without duplicating join points.
func cubicBezier(p0, c1, c2, p3 pt, steps int) []pt {
	out := make([]pt, 0, steps)
	for i := 1; i <= steps; i++ {
		t := float64(i) / float64(steps)
		mt := 1 - t
		x := mt*mt*mt*p0.x + 3*mt*mt*t*c1.x + 3*mt*t*t*c2.x + t*t*t*p3.x
		y := mt*mt*mt*p0.y + 3*mt*mt*t*c1.y + 3*mt*t*t*c2.y + t*t*t*p3.y
		out = append(out, pt{x, y})
	}
	return out
}

// shieldPolygon reproduces the SVG path
// "M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6z" (24x24 viewBox) as a
// closed polygon in the same 24-unit coordinate space.
func shieldPolygon() []pt {
	p0 := pt{12, 2}
	p1 := pt{3, 6}
	p2 := pt{3, 12}
	p3 := pt{12, 22} // p2 + (9, 10)
	c1a := pt{3, 17} // p2 + (0, 5)
	c2a := pt{6.8, 21.3}
	p4 := pt{21, 12} // p3 + (9, -10)
	c1b := pt{17.2, 21.3}
	c2b := pt{21, 17}
	p5 := pt{21, 6}

	poly := []pt{p0, p1, p2}
	poly = append(poly, cubicBezier(p2, c1a, c2a, p3, 20)...)
	poly = append(poly, cubicBezier(p3, c1b, c2b, p4, 20)...)
	poly = append(poly, p5)
	return poly
}

// checkStrokes reproduces the polyline "8.5 12.2 11 14.7 15.5 9.7" from the
// "shield-check" symbol, as line segments to stroke.
func checkSegments() [][2]pt {
	a := pt{8.5, 12.2}
	b := pt{11, 14.7}
	c := pt{15.5, 9.7}
	return [][2]pt{{a, b}, {b, c}}
}

func bbox(poly []pt) (minX, minY, maxX, maxY float64) {
	minX, minY = math.Inf(1), math.Inf(1)
	maxX, maxY = math.Inf(-1), math.Inf(-1)
	for _, p := range poly {
		minX, maxX = math.Min(minX, p.x), math.Max(maxX, p.x)
		minY, maxY = math.Min(minY, p.y), math.Max(maxY, p.y)
	}
	return
}

func centroid(poly []pt) pt {
	var sx, sy float64
	for _, p := range poly {
		sx += p.x
		sy += p.y
	}
	n := float64(len(poly))
	return pt{sx / n, sy / n}
}

// pointInPolygon is a standard ray-casting test.
func pointInPolygon(x, y float64, poly []pt) bool {
	inside := false
	n := len(poly)
	for i, j := 0, n-1; i < n; j, i = i, i+1 {
		pi, pj := poly[i], poly[j]
		if (pi.y > y) != (pj.y > y) &&
			x < (pj.x-pi.x)*(y-pi.y)/(pj.y-pi.y)+pi.x {
			inside = !inside
		}
	}
	return inside
}

func distToSegment(x, y float64, a, b pt) float64 {
	vx, vy := b.x-a.x, b.y-a.y
	wx, wy := x-a.x, y-a.y
	len2 := vx*vx + vy*vy
	t := 0.0
	if len2 > 0 {
		t = (wx*vx + wy*vy) / len2
	}
	t = math.Max(0, math.Min(1, t))
	px, py := a.x+t*vx, a.y+t*vy
	dx, dy := x-px, y-py
	return math.Sqrt(dx*dx + dy*dy)
}

// renderIcon rasterizes the shield mark at size x size pixels: a filled
// shield with a darker ring (same technique as the tray icons' ring, just
// against a polygon instead of a circle) plus a white check stroke on top,
// anti-aliased via supersampling for the fill and analytic distance-based
// AA for the stroke.
func renderIcon(size int, fill, ring color.NRGBA) *image.NRGBA {
	outer := shieldPolygon()
	c := centroid(outer)
	const shrink = 0.90 // inner (fill) polygon vs. outer (ring) polygon
	inner := make([]pt, len(outer))
	for i, p := range outer {
		inner[i] = pt{c.x + (p.x-c.x)*shrink, c.y + (p.y-c.y)*shrink}
	}

	minX, minY, maxX, maxY := bbox(outer)
	w, h := maxX-minX, maxY-minY
	pad := 0.10 // fraction of canvas kept empty around the mark
	scale := float64(size) * (1 - 2*pad) / math.Max(w, h)
	offX := (float64(size)-w*scale)/2 - minX*scale
	offY := (float64(size)-h*scale)/2 - minY*scale

	toCanvas := func(p pt) pt { return pt{p.x*scale + offX, p.y*scale + offY} }
	outerC := make([]pt, len(outer))
	for i, p := range outer {
		outerC[i] = toCanvas(p)
	}
	innerC := make([]pt, len(inner))
	for i, p := range inner {
		innerC[i] = toCanvas(p)
	}
	segs := checkSegments()
	segsC := make([][2]pt, len(segs))
	for i, s := range segs {
		segsC[i] = [2]pt{toCanvas(s[0]), toCanvas(s[1])}
	}
	strokeR := 1.15 * scale // half-width of the check stroke, in canvas px

	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // supersample grid per axis for the fill/ring AA
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var fillN, ringN int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := float64(x) + (float64(sx)+0.5)/ss
					py := float64(y) + (float64(sy)+0.5)/ss
					if pointInPolygon(px, py, innerC) {
						fillN++
					} else if pointInPolygon(px, py, outerC) {
						ringN++
					}
				}
			}
			total := ss * ss
			covered := fillN + ringN
			if covered == 0 {
				continue
			}
			alpha := float64(covered) / float64(total)
			r := (float64(fill.R)*float64(fillN) + float64(ring.R)*float64(ringN)) / float64(covered)
			g := (float64(fill.G)*float64(fillN) + float64(ring.G)*float64(ringN)) / float64(covered)
			b := (float64(fill.B)*float64(fillN) + float64(ring.B)*float64(ringN)) / float64(covered)

			// Composite the white check mark on top, clipped to this
			// pixel's own shield coverage so it never floats outside the
			// silhouette.
			minD := math.Inf(1)
			for _, s := range segsC {
				minD = math.Min(minD, distToSegment(float64(x)+0.5, float64(y)+0.5, s[0], s[1]))
			}
			checkA := 1 - smoothstep(strokeR-0.75, strokeR+0.75, minD)
			checkA *= alpha
			r = r*(1-checkA) + 255*checkA
			g = g*(1-checkA) + 255*checkA
			b = b*(1-checkA) + 255*checkA

			img.SetNRGBA(x, y, color.NRGBA{R: byte(r), G: byte(g), B: byte(b), A: byte(alpha * 255)})
		}
	}
	return img
}

func smoothstep(edge0, edge1, x float64) float64 {
	if edge1 <= edge0 {
		if x < edge0 {
			return 0
		}
		return 1
	}
	t := math.Max(0, math.Min(1, (x-edge0)/(edge1-edge0)))
	return t * t * (3 - 2*t)
}

// writeICO packs one or more PNG-encoded images (Vista+ PNG-compressed ICO
// entries) into a minimal, valid .ico file. Mirrors tools/genicon/main.go.
func writeICO(path string, imgs []*image.NRGBA) error {
	type entry struct {
		w, h byte
		data []byte
	}
	var entries []entry
	for _, im := range imgs {
		var buf bytes.Buffer
		if err := png.Encode(&buf, im); err != nil {
			return err
		}
		w := im.Bounds().Dx()
		if w >= 256 {
			w = 0
		}
		entries = append(entries, entry{w: byte(w), h: byte(w), data: buf.Bytes()})
	}

	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&out, binary.LittleEndian, uint16(1)) // type = icon
	binary.Write(&out, binary.LittleEndian, uint16(len(entries)))

	offset := uint32(6 + 16*len(entries))
	for _, e := range entries {
		out.WriteByte(e.w)
		out.WriteByte(e.h)
		out.WriteByte(0) // color palette
		out.WriteByte(0) // reserved
		binary.Write(&out, binary.LittleEndian, uint16(1))  // color planes
		binary.Write(&out, binary.LittleEndian, uint16(32)) // bits per pixel
		binary.Write(&out, binary.LittleEndian, uint32(len(e.data)))
		binary.Write(&out, binary.LittleEndian, offset)
		offset += uint32(len(e.data))
	}
	for _, e := range entries {
		out.Write(e.data)
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func main() {
	outDir := "assets/appicon"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	blue := color.NRGBA{0x2a, 0x78, 0xd6, 0xff}
	blueRing := color.NRGBA{0x18, 0x4f, 0x95, 0xff}

	sizes := []int{16, 24, 32, 48, 64, 128, 256}
	imgs := make([]*image.NRGBA, len(sizes))
	for i, s := range sizes {
		imgs[i] = renderIcon(s, blue, blueRing)
	}

	out := filepath.Join(outDir, "icon.ico")
	if err := writeICO(out, imgs); err != nil {
		log.Fatal(err)
	}
	log.Println("wrote", out)
	log.Println("next: embed it into the exe with go-winres and assets/appicon/winres.json, e.g.")
	log.Println(`  go install github.com/tc-hib/go-winres@latest`)
	log.Println(`  go-winres make --in assets/appicon/winres.json --arch amd64 --out cmd/netwatch/rsrc`)
	log.Println(`  (NOT "go-winres simply" — it puts the icon at resource ID 1, but Wails'`)
	log.Println(`  window/taskbar icon loader hardcodes ID 3 (winc.AppIconID); winres.json`)
	log.Println(`  pins it there explicitly via "RT_GROUP_ICON" -> "#3". See CLAUDE.md.)`)
}
