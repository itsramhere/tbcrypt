// Command genicon generates the embedded 16/32-pixel padlock ICO without tools.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func generate() error {
	var images [][]byte
	for _, size := range []int{16, 32} {
		img := image.NewNRGBA(image.Rect(0, 0, size, size))
		scale := size / 16
		fill := func(x, y int, c color.NRGBA) {
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetNRGBA(x*scale+dx, y*scale+dy, c)
				}
			}
		}
		for y := 2; y < 15; y++ {
			for x := 3; x < 13; x++ {
				if y >= 7 {
					fill(x, y, color.NRGBA{R: 32, G: 116, B: 196, A: 255})
				} else if (x == 5 || x == 10) && y >= 3 || y == 2 && x >= 6 && x <= 9 {
					fill(x, y, color.NRGBA{R: 190, G: 203, B: 214, A: 255})
				}
			}
		}
		for y := 10; y < 13; y++ {
			fill(7, y, color.NRGBA{R: 240, G: 245, B: 250, A: 255})
			fill(8, y, color.NRGBA{R: 240, G: 245, B: 250, A: 255})
		}
		var b bytes.Buffer
		if err := png.Encode(&b, img); err != nil {
			return err
		}
		images = append(images, b.Bytes())
	}
	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, [3]uint16{0, 1, 2})
	offset := uint32(6 + 16*len(images))
	for i, data := range images {
		size := byte(16 * (i + 1))
		ico.Write([]byte{size, size, 0, 0})
		binary.Write(&ico, binary.LittleEndian, uint16(1))
		binary.Write(&ico, binary.LittleEndian, uint16(32))
		binary.Write(&ico, binary.LittleEndian, uint32(len(data)))
		binary.Write(&ico, binary.LittleEndian, offset)
		offset += uint32(len(data))
	}
	for _, data := range images {
		ico.Write(data)
	}
	dest := filepath.Join("internal", "tray", "assets", "icon.ico")
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	return os.WriteFile(dest, ico.Bytes(), 0644)
}
