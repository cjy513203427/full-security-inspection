//go:build ignore

// One-off generator for the tray icons committed under
// internal/tray/assets/*.ico. Run with:
//
//	go run tools/genicon/main.go
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

func circleImage(size int, fill color.NRGBA, ring color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	c := float64(size) / 2
	r := c - 1.5
	ringW := math.Max(1.2, float64(size)*0.09)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) + 0.5 - c
			dy := float64(y) + 0.5 - c
			d := math.Sqrt(dx*dx + dy*dy)
			switch {
			case d <= r-ringW:
				img.Set(x, y, fill)
			case d <= r:
				img.Set(x, y, ring)
			default:
				img.Set(x, y, color.NRGBA{0, 0, 0, 0})
			}
		}
	}
	return img
}

// writeICO packs one or more PNG-encoded images (Vista+ PNG-compressed ICO
// entries) into a minimal, valid .ico file.
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
	// ICONDIR
	binary.Write(&out, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&out, binary.LittleEndian, uint16(1)) // type = icon
	binary.Write(&out, binary.LittleEndian, uint16(len(entries)))

	offset := uint32(6 + 16*len(entries))
	for _, e := range entries {
		out.WriteByte(e.w)
		out.WriteByte(e.h)
		out.WriteByte(0)                                    // color palette
		out.WriteByte(0)                                    // reserved
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
	outDir := "internal/tray/assets"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	blue := color.NRGBA{0x2a, 0x78, 0xd6, 0xff}
	blueRing := color.NRGBA{0x18, 0x4f, 0x95, 0xff}
	red := color.NRGBA{0xd0, 0x3b, 0x3b, 0xff}
	redRing := color.NRGBA{0x8f, 0x22, 0x22, 0xff}

	normal := []*image.NRGBA{circleImage(16, blue, blueRing), circleImage(32, blue, blueRing), circleImage(48, blue, blueRing)}
	alert := []*image.NRGBA{circleImage(16, red, redRing), circleImage(32, red, redRing), circleImage(48, red, redRing)}

	if err := writeICO(filepath.Join(outDir, "icon_normal.ico"), normal); err != nil {
		log.Fatal(err)
	}
	if err := writeICO(filepath.Join(outDir, "icon_alert.ico"), alert); err != nil {
		log.Fatal(err)
	}
	log.Println("wrote", outDir, "icon_normal.ico + icon_alert.ico")
}
