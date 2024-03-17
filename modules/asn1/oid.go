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

	readableOID := "unknown"
	name, ok := GetKnownOIDName(i)
	if ok {
		readableOID = name
	}

	return fmt.Sprintf("ObjectIdentifier[%s (%s)]", strings.Join(parts, "."), readableOID)
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
	OidITUT         = NewObjectIdentifier(0) // 0
	OidISO          = NewObjectIdentifier(1) // 1
	OidJointISOITUT = NewObjectIdentifier(2) // 2

	OidStandard                = OidISO.Child(0) // 1.0
	OidRegistrationAuthorities = OidISO.Child(1) // 1.1
	OidMemberBody              = OidISO.Child(2) // 1.2
	OidISOIdentifiedOrg        = OidISO.Child(3) // 1.3

	OidANSIX962      = OidMemberBody.Child(840, 10045) // 1.2.840.10045
	OidX962FieldType = OidANSIX962.Child(1)            // 1.2.840.10045.1
	OidX962KeyTYpe   = OidANSIX962.Child(2)            // 1.2.840.10045.2
	OidX962Curves    = OidANSIX962.Child(3)            // 1.2.840.10045.3
	OidX962Signature = OidANSIX962.Child(4)            // 1.2.840.10045.4
	OidX962Module    = OidANSIX962.Child(5)            // 1.2.840.10045.5

	OidECPublicKey                  = OidX962KeyTYpe.Child(1)           // 1.2.840.10045.2.1
	OidPrimeCurve                   = OidX962Curves.Child(1)            // 1.2.840.10045.3.1
	OidPrimeCurveP192v1             = OidPrimeCurve.Child(1)            // 1.2.840.10045.3.1.1
	OidPrimeCurveP192v2             = OidPrimeCurve.Child(2)            // 1.2.840.10045.3.1.2
	OidPrimeCurveP192v3             = OidPrimeCurve.Child(3)            // 1.2.840.10045.3.1.3
	OidPrimeCurveP239v1             = OidPrimeCurve.Child(4)            // 1.2.840.10045.3.1.4
	OidPrimeCurveP239v2             = OidPrimeCurve.Child(5)            // 1.2.840.10045.3.1.5
	OidPrimeCurveP239v3             = OidPrimeCurve.Child(6)            // 1.2.840.10045.3.1.6
	OidPrimeCurveP256v1             = OidPrimeCurve.Child(7)            // 1.2.840.10045.3.1.7
	OidSignatureECDSAWithSha1       = OidX962Signature.Child(1)         // 1.2.840.10045.4.1
	OidSignaureECDSAWithRecommanded = OidX962Signature.Child(2)         // 1.2.840.10045.4.2
	OidSignaureECDSAWithSha2        = OidX962Signature.Child(3)         // 1.2.840.10045.4.3
	OidSignaureECDSAWithSHA224      = OidSignaureECDSAWithSha2.Child(1) // 1.2.840.10045.4.3.1
	OidSignaureECDSAWithSHA256      = OidSignaureECDSAWithSha2.Child(2) // 1.2.840.10045.4.3.2
	OidSignaureECDSAWithSHA384      = OidSignaureECDSAWithSha2.Child(3) // 1.2.840.10045.4.3.3
	OidSignaureECDSAWithSHA512      = OidSignaureECDSAWithSha2.Child(4) // 1.2.840.10045.4.3.4

	OidCerticom                = OidISOIdentifiedOrg.Child(132) // 1.3.132
	OidCerticomCurve           = OidCerticom.Child(0)           // 1.3.132.0
	OidCerticomCurveAnsiT163k1 = OidCerticomCurve.Child(1)      // 1.3.132.1
	OidCerticomCurveAnsiT163r1 = OidCerticomCurve.Child(2)      // 1.3.132.2
	OidCerticomCurveAnsiT239k1 = OidCerticomCurve.Child(3)      // 1.3.132.3
	OidCerticomCurveSecT113r1  = OidCerticomCurve.Child(4)      // 1.3.132.4
	OidCerticomCurveSecT113r2  = OidCerticomCurve.Child(5)      // 1.3.132.5
	OidCerticomCurveSecP112r1  = OidCerticomCurve.Child(6)      // 1.3.132.6
	OidCerticomCurveSecP112r2  = OidCerticomCurve.Child(7)      // 1.3.132.7
	OidCerticomCurveAnsiP160r1 = OidCerticomCurve.Child(8)      // 1.3.132.8
	OidCerticomCurveAnsiP160k2 = OidCerticomCurve.Child(9)      // 1.3.132.9
	OidCerticomCurveAnsiP256k1 = OidCerticomCurve.Child(10)     // 1.3.132.10
	OidCerticomCurveAnsiT163r2 = OidCerticomCurve.Child(15)     // 1.3.132.15
	OidCerticomCurveAnsiT283k1 = OidCerticomCurve.Child(16)     // 1.3.132.16
	OidCerticomCurveAnsiT283r1 = OidCerticomCurve.Child(17)     // 1.3.132.17
	OidCerticomCurveSecT131r1  = OidCerticomCurve.Child(22)     // 1.3.132.22
	OidCerticomCurveSecT131r2  = OidCerticomCurve.Child(23)     // 1.3.132.23
	OidCerticomCurveAnsiT193r1 = OidCerticomCurve.Child(24)     // 1.3.132.24
	OidCerticomCurveAnsiT193r2 = OidCerticomCurve.Child(25)     // 1.3.132.25
	OidCerticomCurveAnsiT233k1 = OidCerticomCurve.Child(26)     // 1.3.132.26
	OidCerticomCurveAnsiT233r1 = OidCerticomCurve.Child(27)     // 1.3.132.27
	OidCerticomCurveSecP128r1  = OidCerticomCurve.Child(28)     // 1.3.132.28
	OidCerticomCurveSecP128r2  = OidCerticomCurve.Child(29)     // 1.3.132.29
	OidCerticomCurveAnsiP160r2 = OidCerticomCurve.Child(30)     // 1.3.132.30
	OidCerticomCurveAnsiP192k1 = OidCerticomCurve.Child(31)     // 1.3.132.31
	OidCerticomCurveAnsiP224k1 = OidCerticomCurve.Child(32)     // 1.3.132.32
	OidCerticomCurveAnsiP224r1 = OidCerticomCurve.Child(33)     // 1.3.132.33
	OidCerticomCurveAnsiP384r1 = OidCerticomCurve.Child(34)     // 1.3.132.34
	OidCerticomCurveAnsiP521r1 = OidCerticomCurve.Child(35)     // 1.3.132.35
	OidCerticomCurveAnsiT409k1 = OidCerticomCurve.Child(36)     // 1.3.132.36
	OidCerticomCurveAnsiT409r1 = OidCerticomCurve.Child(37)     // 1.3.132.37
	OidCerticomCurveAnsiT571k1 = OidCerticomCurve.Child(38)     // 1.3.132.38
	OidCerticomCurveAnsiT571r1 = OidCerticomCurve.Child(39)     // 1.3.132.39

	OidRSADsi   = OidMemberBody.Child(840, 113549) // 1.2.840.113549
	OidRSAPkcs1 = OidRSADsi.Child(1, 1)            // 1.2.840.113549.1.1

	OidRSAPkcs1RSAEncryption        = OidRSAPkcs1.Child(1)  // 1.2.840.113549.1.1.1
	OidRSAPkcs1MD2WithRSA           = OidRSAPkcs1.Child(2)  // 1.2.840.113549.1.1.2
	OidRSAPkcs1MD4WithRSA           = OidRSAPkcs1.Child(3)  // 1.2.840.113549.1.1.3
	OidRSAPkcs1MD5WithRSA           = OidRSAPkcs1.Child(4)  // 1.2.840.113549.1.1.4
	OidRSAPkcs1SHA1WithRSA          = OidRSAPkcs1.Child(5)  // 1.2.840.113549.1.1.5
	OidRSAPkcs1RSAOaepEncryptionSET = OidRSAPkcs1.Child(6)  // 1.2.840.113549.1.1.6
	OidRSAPkcs1IdRSASEOaep          = OidRSAPkcs1.Child(7)  // 1.2.840.113549.1.1.7
	OidRSAPkcs1IdMgf1               = OidRSAPkcs1.Child(8)  // 1.2.840.113549.1.1.8
	OidRSAPkcs1IdPSpecified         = OidRSAPkcs1.Child(9)  // 1.2.840.113549.1.1.9
	OidRSAPkcs1RsaSsaPss            = OidRSAPkcs1.Child(10) // 1.2.840.113549.1.1.10
	OidRSAPkcs1Sha256WithRSA        = OidRSAPkcs1.Child(11) // 1.2.840.113549.1.1.11
	OidRSAPkcs1Sha384WithRSA        = OidRSAPkcs1.Child(12) // 1.2.840.113549.1.1.12
	OidRSAPkcs1Sha512WithRSA        = OidRSAPkcs1.Child(13) // 1.2.840.113549.1.1.13
	OidRSAPkcs1Sha224WithRSA        = OidRSAPkcs1.Child(14) // 1.2.840.113549.1.1.14

	OidDirectoryServices = OidJointISOITUT.Child(5) // 2.5

	OidDirectoryAttributeTypes         = OidDirectoryServices.Child(4)        // 2.5.4
	OidObjectClass                     = OidDirectoryAttributeTypes.Child(0)  // 2.5.4.0
	OidAliasedEntryName                = OidDirectoryAttributeTypes.Child(1)  // 2.5.4.1
	OidKnowledgeInformation            = OidDirectoryAttributeTypes.Child(2)  // 2.5.4.2
	OidCommonName                      = OidDirectoryAttributeTypes.Child(3)  // 2.5.4.3
	OidSurname                         = OidDirectoryAttributeTypes.Child(4)  // 2.5.4.4
	OidSerialNumber                    = OidDirectoryAttributeTypes.Child(5)  // 2.5.4.5
	OidCountryName                     = OidDirectoryAttributeTypes.Child(6)  // 2.5.4.6
	OidLocalityName                    = OidDirectoryAttributeTypes.Child(7)  // 2.5.4.7
	OidStateOrProvinceName             = OidDirectoryAttributeTypes.Child(8)  // 2.5.4.8
	OidStreetAddress                   = OidDirectoryAttributeTypes.Child(9)  // 2.5.4.9
	OidOrganizationName                = OidDirectoryAttributeTypes.Child(10) // 2.5.4.10
	OidOrganizationalUnitName          = OidDirectoryAttributeTypes.Child(11) // 2.5.4.11
	OidTitle                           = OidDirectoryAttributeTypes.Child(12) // 2.5.4.12
	OidDescription                     = OidDirectoryAttributeTypes.Child(13) // 2.5.4.13
	OidSearchGuide                     = OidDirectoryAttributeTypes.Child(14) // 2.5.4.14
	OidCertificateExtension            = OidDirectoryServices.Child(29)       // 2.5.29
	OidExtensionSubjectKeyIdentifier   = OidCertificateExtension.Child(14)    // 2.5.29.14
	OidExtensionKeyUsage               = OidCertificateExtension.Child(15)    // 2.5.29.15
	OidExtensionSubjectAltName         = OidCertificateExtension.Child(17)    // 2.5.29.17
	OidExtensionBasicConstraints       = OidCertificateExtension.Child(19)    // 2.5.29.19
	OidExtensionCRLDistributionPoints  = OidCertificateExtension.Child(31)    // 2.5.29.31
	OidExtensionCertificatePolicies    = OidCertificateExtension.Child(32)    // 2.5.29.32
	OidExtensionAuthorityKeyIdentifier = OidCertificateExtension.Child(35)    // 2.5.29.35
	OidExtensionExtKeyUsage            = OidCertificateExtension.Child(37)    // 2.5.29.37
)

type nameNode struct {
	Name     string
	Children map[uint64]*nameNode
}

func newNameNode(name string) *nameNode {
	return &nameNode{
		Name:     name,
		Children: make(map[uint64]*nameNode),
	}
}

func (n *nameNode) Register(oid *ASN1ObjectIdentifier, name string) {
	node := n
	for i, id := range *oid {
		final := i == len(*oid)-1
		child, ok := node.Children[id]
		if !ok {
			child = newNameNode("")
			if final {
				child.Name = name
			}

			node.Children[id] = child
		}

		node = child
	}
}

func (n *nameNode) Find(oid *ASN1ObjectIdentifier) (string, bool) {
	node := n
	for _, id := range *oid {
		child, ok := node.Children[id]
		if !ok {
			return "", false
		}

		node = child
	}

	return node.Name, true
}

var nameRoot = newNameNode("Root")

var oidNames = []struct {
	oid  *ASN1ObjectIdentifier
	name string
}{
	{OidITUT, "itu-t"},
	{OidISO, "iso"},
	{OidJointISOITUT, "joint-iso-itu-t"},

	{OidECPublicKey, "EC Public Key"},                           // 1.2.840.10045.2.1
	{OidPrimeCurve, "Prime Curve"},                              // 1.2.840.10045.3.1
	{OidPrimeCurveP192v1, "Prime Curve P192v1"},                 // 1.2.840.10045.3.1.1
	{OidPrimeCurveP192v2, "Prime Curve P192v2"},                 // 1.2.840.10045.3.1.2
	{OidPrimeCurveP192v3, "Prime Curve P192v3"},                 // 1.2.840.10045.3.1.3
	{OidPrimeCurveP239v1, "Prime Curve P239v1"},                 // 1.2.840.10045.3.1.4
	{OidPrimeCurveP239v2, "Prime Curve P239v2"},                 // 1.2.840.10045.3.1.5
	{OidPrimeCurveP239v3, "Prime Curve P239v3"},                 // 1.2.840.10045.3.1.6
	{OidPrimeCurveP256v1, "Prime Curve P256v1"},                 // 1.2.840.10045.3.1.7
	{OidSignatureECDSAWithSha1, "ECDSA with SHA1"},              // 1.2.840.10045.4.1
	{OidSignaureECDSAWithRecommanded, "ECDSA with Recommanded"}, // 1.2.840.10045.4.2
	{OidSignaureECDSAWithSha2, "ECDSA with SHA2"},               // 1.2.840.10045.4.3
	{OidSignaureECDSAWithSHA224, "ECDSA with SHA224"},           // 1.2.840.10045.4.3.1
	{OidSignaureECDSAWithSHA256, "ECDSA with SHA256"},           // 1.2.840.10045.4.3.2
	{OidSignaureECDSAWithSHA384, "ECDSA with SHA384"},           // 1.2.840.10045.4.3.3
	{OidSignaureECDSAWithSHA512, "ECDSA with SHA512"},           // 1.2.840.10045.4.3.4

	{OidDirectoryAttributeTypes, "Directory Attribute Types"},
	{OidObjectClass, "Object Class"},
	{OidAliasedEntryName, "Aliased Entry Name"},
	{OidKnowledgeInformation, "Knowledge Information"},
	{OidCommonName, "Common Name (CN)"},
	{OidSurname, "Surname"},
	{OidSerialNumber, "Serial Number"},
	{OidCountryName, "Country Name (C)"},
	{OidLocalityName, "Locality Name (L)"},
	{OidStateOrProvinceName, "State or Province Name (S)"},
	{OidStreetAddress, "Street Address (ST)"},
	{OidOrganizationName, "Organization Name (O)"},
	{OidOrganizationalUnitName, "Organizational Unit Name (OU)"},

	{OidExtensionSubjectKeyIdentifier, "Subject Key Identifier"},
	{OidExtensionKeyUsage, "Key Usage"},
	{OidExtensionSubjectAltName, "Subject Alternative Name"},
	{OidExtensionBasicConstraints, "Basic Constraints"},
	{OidExtensionCRLDistributionPoints, "CRL Distribution Points"},
	{OidExtensionCertificatePolicies, "Certificate Policies"},
	{OidExtensionAuthorityKeyIdentifier, "Authority Key Identifier"},
	{OidExtensionExtKeyUsage, "Extended Key Usage"},

	{OidCerticomCurve, "Certicom Curve"},
	{OidCerticomCurveAnsiT163k1, "Certicom Curve ANSI T163k1"},
	{OidCerticomCurveAnsiT163r1, "Certicom Curve ANSI T163r1"},
	{OidCerticomCurveAnsiT239k1, "Certicom Curve ANSI T239k1"},
	{OidCerticomCurveSecT113r1, "Certicom Curve SEC T113r1"},
	{OidCerticomCurveSecT113r2, "Certicom Curve SEC T113r2"},
	{OidCerticomCurveSecP112r1, "Certicom Curve SEC P112r1"},
	{OidCerticomCurveSecP112r2, "Certicom Curve SEC P112r2"},
	{OidCerticomCurveAnsiP160r1, "Certicom Curve ANSI P160r1"},
	{OidCerticomCurveAnsiP160k2, "Certicom Curve ANSI P160k2"},
	{OidCerticomCurveAnsiP256k1, "Certicom Curve ANSI P256k1"},
	{OidCerticomCurveAnsiT163r2, "Certicom Curve ANSI T163r2"},
	{OidCerticomCurveAnsiT283k1, "Certicom Curve ANSI T283k1"},
	{OidCerticomCurveAnsiT283r1, "Certicom Curve ANSI T283r1"},
	{OidCerticomCurveSecT131r1, "Certicom Curve SEC T131r1"},
	{OidCerticomCurveSecT131r2, "Certicom Curve SEC T131r2"},
	{OidCerticomCurveAnsiT193r1, "Certicom Curve ANSI T193r1"},
	{OidCerticomCurveAnsiT193r2, "Certicom Curve ANSI T193r2"},
	{OidCerticomCurveAnsiT233k1, "Certicom Curve ANSI T233k1"},
	{OidCerticomCurveAnsiT233r1, "Certicom Curve ANSI T233r1"},
	{OidCerticomCurveSecP128r1, "Certicom Curve SEC P128r1"},
	{OidCerticomCurveSecP128r2, "Certicom Curve SEC P128r2"},
	{OidCerticomCurveAnsiP160r2, "Certicom Curve ANSI P160r2"},
	{OidCerticomCurveAnsiP192k1, "Certicom Curve ANSI P192k1"},
	{OidCerticomCurveAnsiP224k1, "Certicom Curve ANSI P224k1"},
	{OidCerticomCurveAnsiP224r1, "Certicom Curve ANSI P224r1"},
	{OidCerticomCurveAnsiP384r1, "Certicom Curve ANSI P384r1"},
	{OidCerticomCurveAnsiP521r1, "Certicom Curve ANSI P521r1"},
	{OidCerticomCurveAnsiT409k1, "Certicom Curve ANSI T409k1"},
	{OidCerticomCurveAnsiT409r1, "Certicom Curve ANSI T409r1"},
	{OidCerticomCurveAnsiT571k1, "Certicom Curve ANSI T571k1"},
	{OidCerticomCurveAnsiT571r1, "Certicom Curve ANSI T571r1"},
}

func init() {
	for _, n := range oidNames {
		nameRoot.Register(n.oid, n.name)
	}
}

func GetKnownOIDName(oid *ASN1ObjectIdentifier) (string, bool) {
	return nameRoot.Find(oid)
}
