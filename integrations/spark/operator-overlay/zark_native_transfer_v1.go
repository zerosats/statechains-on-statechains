// Install in spark/so/transfer with root-v1.patch. Legacy MPC submissions keep
// their exact three-job contract; only this explicit packet selects root2.
package transfer

import (
	"bytes"
	"fmt"
	"slices"
	"github.com/lightsparkdev/spark/so"
)

const ZarkNativeRootMagic = "ZARK-NATIVE-ROOT-v1\x00"

func parseZarkNativeRootProfile(sealed map[so.Identifier]map[uint32][]byte, positions []uint32, leaves int) ([]byte,error) {
	var selected []byte
	for _,parts := range sealed {for _,raw := range parts {if bytes.HasPrefix(raw,[]byte(ZarkNativeRootMagic)) {selected = raw;break}}}
	if selected == nil {return nil,nil}
	if leaves != 1 || !slices.Equal(positions,[]uint32{1,2}) || len(selected) > 64*1024 {
		return nil,fmt.Errorf("native root profile requires one leaf, positions 1/2 and a bounded packet")
	}
	for _,parts := range sealed {
		if len(parts) != 2 {return nil,fmt.Errorf("native root packet position coverage differs")}
		for _,position := range positions {if !bytes.Equal(parts[position],selected) {return nil,fmt.Errorf("native root packet differs across operators/positions")}}
	}
	return slices.Clone(selected),nil
}

func (s *MpcSubmission) ZarkNativeRootPacket() []byte {return slices.Clone(s.zarkNativeRootPacket)}
