package asn1

import (
	"fmt"
	"strings"
)

type ASN1ObjectIdentifier []uint64

func NewObjectIdentifier(ids ...uint64) *ASN1ObjectIdentifier {
	oid := ASN1ObjectIdentifier(ids)
	return &oid
}

func (i *ASN1ObjectIdentifier) Tag() *Tag {
	t := &Tag{
		Class:  TagClassUniversal,
		PC:     TagPrimitive, // X.690 8.19.1, object identifier value SHALL BE primitive
		Number: TagObjectIdentifier,
	}

	return t
}

func (i *ASN1ObjectIdentifier) ContentLength() Length {
	length := 1

	for j := 2; j < len(*i); j++ {
		length += getBase128UintByteSize((*i)[j])
	}

	return Length(length)
}

func (i *ASN1ObjectIdentifier) WriteContentTo(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, i.ContentLength().Int()); err != nil {
		return -1, err
	}

	firstOctet := (*i)[0]*40 + (*i)[1]
	buffer[offset] = byte(firstOctet)
	next := offset + 1
	for j := 2; j < len(*i); j++ {
		n := (*i)[j]
		size := getBase128UintByteSize(n)
		next = writeBase128Uint(buffer, next, n, size)
	}

	return next, nil
}

func (i *ASN1ObjectIdentifier) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	length := info.Length.Int()
	if err := checkBufferSize(buffer, offset, length); err != nil {
		return err
	}

	firstOctet := buffer[offset]
	*i = append((*i)[:0], uint64(firstOctet/40), uint64(firstOctet%40))
	next := offset + 1
	for next < offset+length {
		var n uint64
		n, next = readBase128Uint(buffer, next)
		if next < 0 {
			return fmt.Errorf("asn1: invalid object identifier at byte %d", next)
		}

		*i = append(*i, n)
	}

	return nil
}

func (i *ASN1ObjectIdentifier) String() string {
	parts := make([]string, len(*i))
	for j, id := range *i {
		parts[j] = fmt.Sprintf("%d", id)
	}

	return fmt.Sprintf("ObjectIdentifier[%s]", strings.Join(parts, "."))
}

func (i *ASN1ObjectIdentifier) PrettyString(indent string) string {
	return indent + i.String()
}

func (i *ASN1ObjectIdentifier) Child(n ...uint64) *ASN1ObjectIdentifier {
	array := make([]uint64, len(*i)+len(n))
	copy(array, *i)
	copy(array[len(*i):], n)

	oid := ASN1ObjectIdentifier(array)
	return &oid
}

func (i *ASN1ObjectIdentifier) Equal(other ASN1Object) bool {
	if otherOID, ok := other.(*ASN1ObjectIdentifier); ok {
		if len(*i) != len(*otherOID) {
			return false
		}

		for j, id := range *i {
			if id != (*otherOID)[j] {
				return false
			}
		}

		return true
	}

	return false
}

var (
	OidITUT         = NewObjectIdentifier(0)
	OidISO          = NewObjectIdentifier(1)
	OidJointISOITUT = NewObjectIdentifier(2)

	OidStandard                = OidISO.Child(0)
	OidRegistrationAuthorities = OidISO.Child(1)
	OidMemberBody              = OidISO.Child(2)
	OidISOIdentifiedOrg        = OidISO.Child(3)

	OidANSIX962    = OidMemberBody.Child(840, 10045)
	OidECPublicKey = OidANSIX962.Child(2, 1)

	OidCerticom                = OidISOIdentifiedOrg.Child(132)
	OidCerticomCurve           = OidCerticom.Child(0)
	OidCerticomCurveAnsiT163k1 = OidCerticomCurve.Child(1)
	OidCerticomCurveAnsiT163r1 = OidCerticomCurve.Child(2)
	OidCerticomCurveAnsiT239k1 = OidCerticomCurve.Child(3)
	OidCerticomCurveSecT113r1  = OidCerticomCurve.Child(4)
	OidCerticomCurveSecT113r2  = OidCerticomCurve.Child(5)
	OidCerticomCurveSecP112r1  = OidCerticomCurve.Child(6)
	OidCerticomCurveSecP112r2  = OidCerticomCurve.Child(7)
	OidCerticomCurveAnsiP160r1 = OidCerticomCurve.Child(8)
	OidCerticomCurveAnsiP160k2 = OidCerticomCurve.Child(9)
	OidCerticomCurveAnsiP256k1 = OidCerticomCurve.Child(10)
	OidCerticomCurveAnsiT163r2 = OidCerticomCurve.Child(15)
	OidCerticomCurveAnsiT283k1 = OidCerticomCurve.Child(16)
	OidCerticomCurveAnsiT283r1 = OidCerticomCurve.Child(17)
	OidCerticomCurveSect131r1  = OidCerticomCurve.Child(22)
	OidCerticomCurveSecT131r2  = OidCerticomCurve.Child(23)
	OidCerticomCurveAnsiT193r1 = OidCerticomCurve.Child(24)
	OidCerticomCurveAnsiT193r2 = OidCerticomCurve.Child(25)
	OidCerticomCurveAnsiT233k1 = OidCerticomCurve.Child(26)
	OidCerticomCurveAnsiT233r1 = OidCerticomCurve.Child(27)
	OidCerticomCurveSecP128r1  = OidCerticomCurve.Child(28)
	OidCerticomCurveSecP128r2  = OidCerticomCurve.Child(29)
	OidCerticomCurveAnsiP160r2 = OidCerticomCurve.Child(30)
	OidCerticomCurveAnsiP192k1 = OidCerticomCurve.Child(31)
	OidCerticomCurveAnsiP224k1 = OidCerticomCurve.Child(32)
	OidCerticomCurveAnsiP224r1 = OidCerticomCurve.Child(33)
	OidCerticomCurveAnsiP384r1 = OidCerticomCurve.Child(34)
	OidCerticomCurveAnsiP521r1 = OidCerticomCurve.Child(35)
	OidCerticomCurveAnsiT409k1 = OidCerticomCurve.Child(36)
	OidCerticomCurveAnsiT409r1 = OidCerticomCurve.Child(37)
	OidCerticomCurveAnsiT571k1 = OidCerticomCurve.Child(38)
	OidCerticomCurveAnsiT571r1 = OidCerticomCurve.Child(39)

	OidRSADsi   = OidMemberBody.Child(840, 113549)
	OidRSAPkcs1 = OidRSADsi.Child(1, 1)

	OidRSAPkcs1RSAEncryption        = OidRSAPkcs1.Child(1)
	OidRSAPkcs1MD2WithRSA           = OidRSAPkcs1.Child(2)
	OidRSAPkcs1MD4WithRSA           = OidRSAPkcs1.Child(3)
	OidRSAPkcs1MD5WithRSA           = OidRSAPkcs1.Child(4)
	OidRSAPkcs1SHA1WithRSA          = OidRSAPkcs1.Child(5)
	OidRSAPkcs1RSAOaepEncryptionSET = OidRSAPkcs1.Child(6)
	OidRSAPkcs1IdRSASEOaep          = OidRSAPkcs1.Child(7)
	OidRSAPkcs1IdMgf1               = OidRSAPkcs1.Child(8)
	OidRSAPkcs1IdPSpecified         = OidRSAPkcs1.Child(9)
	OidRSAPkcs1RsaSsaPss            = OidRSAPkcs1.Child(10)
	OidRSAPkcs1Sha256WithRSA        = OidRSAPkcs1.Child(11)
	OidRSAPkcs1Sha384WithRSA        = OidRSAPkcs1.Child(12)
	OidRSAPkcs1Sha512WithRSA        = OidRSAPkcs1.Child(13)
	OidRSAPkcs1Sha224WithRSA        = OidRSAPkcs1.Child(14)
)
