package asn1

import (
	"fmt"
)

func checkSequenceElementType(seq *ASN1Sequence, tagTypes ...uint64) error {
	for i, tagType := range tagTypes {
		if (*seq)[i].Tag().Number != tagType {
			return fmt.Errorf(
				"asn1: check sequence element type: invalid tag type %s on index %d, expected %s",
				(*seq)[i].Tag().String(), i, getTagNumberName(tagType),
			)
		}
	}

	return nil
}

func CanBeX509Certificate(obj ASN1Object) error {
	seq, ok := obj.(*ASN1Sequence)
	if !ok {
		return fmt.Errorf("asn1: check X.509 certificate: not a sequence")
	}

	if len(*seq) != 3 {
		return fmt.Errorf(
			"asn1: check X.509 certificate: invalid number of elements: %d",
			len(*seq),
		)
	}

	if err := checkSequenceElementType(seq, TagSequence, TagSequence, TagBitString); err != nil {
		return fmt.Errorf("asn1: check X.509 certificate: %v", err)
	}

	firstSeq := (*seq)[0].(*ASN1Sequence)
	if len(*firstSeq) < 7 {
		return fmt.Errorf("asn1: check X.509 certificate: invalid number of elements in first sequence: %d", len(*firstSeq))
	}

	if err := checkSequenceElementType(firstSeq,
		TagReserved0, TagInteger, TagSequence, TagSequence, TagSequence, TagSequence, TagSequence); err != nil {
		return fmt.Errorf("asn1: check X.509 certificate: %v", err)
	}

	return nil
}

type SubjectInfo struct {
	CommonName         string // CN
	Country            string // C
	Locality           string // L
	State              string // S
	Street             string // ST
	Organization       string // O
	OrganizationalUnit string // OU
}

func ReadIssuerInfo(cert *ASN1Sequence) (*SubjectInfo, error) {
	if err := CanBeX509Certificate(cert); err != nil {
		return nil, err
	}

	return nil, nil
}
