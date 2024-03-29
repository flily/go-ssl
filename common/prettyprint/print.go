package prettyprint

import (
	"fmt"
	"strings"
)

func binaryHex(data []byte, lineBytes int, indent string) string {
	totalLines := (len(data) + lineBytes - 1) / lineBytes
	lines := make([]string, 0, totalLines)
	lineBuffer := make([]string, 0, 100)
	for i := 0; i < len(data); i += 1 {
		lastByte := ":"
		if i+1 == len(data) {
			lastByte = ""
		}

		lineBuffer = append(lineBuffer,
			fmt.Sprintf("%02x%s", data[i], lastByte))

		if len(lineBuffer) == lineBytes || len(data) == i+1 {
			lines = append(lines, indent+strings.Join(lineBuffer, ""))
			lineBuffer = make([]string, 0, 100)
		}
	}

	return strings.Join(lines, "\n")
}

func binaryConcat(values ...[]byte) []byte {
	length := 0
	for _, value := range values {
		length += len(value)
	}

	result := make([]byte, 0, length)
	for _, value := range values {
		result = append(result, value...)
	}

	return result
}

func PrintBinary(name string, value []byte) {
	fmt.Printf("%s: [%d bytes]\n%s\n",
		name, len(value), binaryHex(value, 15, "    "))
}

func PrintBinaryWithIndent(name string, indent string, value []byte) {
	fmt.Printf("%s: [%d bytes]\n%s\n",
		indent+name, len(value), binaryHex(value, 15, indent+"    "))
}

func PrintBinariesWithIndent(name string, indent string, values ...[]byte) {
	data := binaryConcat(values...)
	fmt.Printf("%s: [%d bytes]\n%s\n",
		indent+name, len(data), binaryHex(data, 15, indent+"    "))
}

func PrintBinaries(name string, values ...[]byte) {
	PrintBinary(name, binaryConcat(values...))
}

// PPrintBinary print value make sure it is positive
func PPrintBinary(name string, value []byte) {
	if len(value) == 0 {
		fmt.Printf("%s: [empty]\n", name)
		return
	}

	length := len(value)
	padded := ""
	first := value[0]
	if first > 0x80 {
		value = append([]byte{0x00}, value...)
		padded = " (padded)"
	}

	fmt.Printf("%s: [%d bytes%s]\n%s\n",
		name, length, padded, binaryHex(value, 15, "    "))
}
