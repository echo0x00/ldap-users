package utils

import (
	"fmt"
	"strconv"
)

var uacMask = map[uint32]string{
	2:        "ACCOUNT_DISABLE",
	8:        "HOMEDIR_REQUIRED",
	16:       "LOCKOUT",
	32:       "PASSWD_NOTREQD",
	64:       "PASSWD_CANT_CHANGE",
	128:      "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
	512:      "NORMAL_ACCOUNT",
	2048:     "INTERDOMAIN_TRUST_ACCOUNT",
	4096:     "WORKSTATION_TRUST_ACCOUNT",
	8192:     "SERVER_TRUST_ACCOUNT",
	65536:    "DONT_EXPIRE_PASSWD",
	131072:   "MNS_LOGON_ACCOUNT",
	262144:   "SMARTCARD_REQUIRED",
	524288:   "TRUSTED_FOR_DELEGATION",
	1048576:  "NOT_DELEGATED",
	2097152:  "USE_DES_KEY_ONLY",
	4194304:  "DONT_REQUIRE_PREAUTH",
	8388608:  "PASSWORD_EXPIRED",
	16777216: "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
	33554432: "NO_AUTH_DATA_REQUIRED",
	67108864: "PARTIAL_SECRETS_ACCOUNT",
}

func IsAccountEnabled(status string) int32 {
	stat, _ := strconv.Atoi(status)
	statusList := decodeUac(uint32(stat))

	var result int32

	for i := 0; i < len(statusList); i++ {
		if statusList[i] == uacMask[2] {
			result = 0
		}
	}

	return result
}

func decodeUac(uac uint32) []string {
	var mask uint32
	var decodedUAC []string
	decodedUAC = []string{}
	for bit := 0; bit < 32; bit++ {
		mask = 1 << bit
		if uac&mask == mask {
			v, found := uacMask[mask]
			if found {
				decodedUAC = append(decodedUAC, v)
			}
		}
	}
	return decodedUAC
}

func DecodeSid(sid []byte) string {
	result := "S-"
	revision := strconv.Itoa(int(sid[0]))
	authority := 0

	for i := 2; i <= 7; i++ {
		authority |= int(sid[i]) << (8 * (5 - (i - 2)))
	}

	result += fmt.Sprintf("%s-%s", revision, strconv.Itoa(authority))

	countSubAuths := int(sid[1]) & 0xFF

	offset := 8
	size := 4
	for j := 0; j < countSubAuths; j++ {
		subAuthority := 0
		for k := 0; k < size; k++ {
			subAuthority |= int(sid[offset+k]&0xFF) << (8 * k)
		}
		result += fmt.Sprintf("-%s", strconv.Itoa(subAuthority))
		offset += size
	}

	return result
}
