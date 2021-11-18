package extension

import "encoding/json"

type Extensions []Extension

func (e Extensions) MarshalJSON() ([]byte, error) {
	s := make(map[string]interface{})

	for _, ext := range e {
		switch v := ext.(type) {
		case *ServerName:
			s["server_name"] = v.ServerName
		case *UseExtendedMasterSecret:
			s["use_extended_master_secret"] = v.Supported
		case *SupportedPointFormats:
			s["supported_point_formats"] = v.PointFormats
		case *SupportedSignatureAlgorithms:
			s["supported_signature_algorithms"] = v.SignatureHashAlgorithms
		case *UseSRTP:
			s["use_srtp"] = v.ProtectionProfiles
		case *SupportedEllipticCurves:
			s["supported_elliptic_curves"] = v.EllipticCurves
		}
	}

	return json.Marshal(s)
}
