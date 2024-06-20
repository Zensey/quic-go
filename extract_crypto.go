package quic

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// ExractCryptoFrame looks for CRYPTO frame in the Initial QUIC packet
func ExractCryptoFrame(data []byte) []byte {

	b := make([]byte, len(data))
	copy(b, data)

	if !wire.IsPotentialQUICPacket(b[0]) {
		// continue
		return nil
	}

	if wire.IsLongHeaderPacket(b[0]) {
		version_b := b[1 : 1+4]
		version := VersionNumber(binary.BigEndian.Uint32(version_b))
		if version != 1 {
			log.Printf("Wrong version: %x\n", version)
			return nil
		}

		hdr, b_, _, err := wire.ParsePacket(b)
		if err != nil {
			log.Println("ParsePacket err:", err)
			return nil
		}
		if hdr.Type != protocol.PacketTypeInitial {
			log.Println("Wrong packet type ", hdr.Type.String())
			return nil
		}

		_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
		extHdr, err := unpackLongHeader(opener, hdr, b_, hdr.Version)
		if err != nil {
			log.Println("unpackLongHeader err:", err)
			return nil
		}
		extHdrLen := extHdr.ParsedLen()
		extHdr.PacketNumber = opener.DecodePacketNumber(extHdr.PacketNumber, extHdr.PacketNumberLen)

		decrypted, err := opener.Open(b_[extHdrLen:extHdrLen], b_[extHdrLen:], extHdr.PacketNumber, b_[:extHdrLen])
		if err != nil {
			log.Println("opener.Open err:", err)
			return nil
		}

		parser := wire.NewFrameParser(false)
		_, f, err := parser.ParseNext(decrypted, protocol.EncryptionInitial, protocol.Version1)
		if err != nil {
			fmt.Println("parser.ParseNext err:", err)
			return nil
		}
		if cryptoFrame, ok := f.(*wire.CryptoFrame); ok {
			return cryptoFrame.Data
		}
	}
	return nil
}
