package proton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type CreateFileReq struct {
	ParentLinkID string

	Name     string // Encrypted File Name
	Hash     string // Encrypted File Name Hash
	MIMEType string // MIME Type

	ContentKeyPacket          string // The block's key packet, encrypted with the node key.
	ContentKeyPacketSignature string // Unencrypted signature of the content session key, signed with the NodeKey

	NodeKey                 string // The private NodeKey, used to decrypt any file/folder content.
	NodePassphrase          string // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
	NodePassphraseSignature string // The signature of the NodePassphrase

	SignatureAddress string // Signature email address used to sign passphrase and name
}

func (createFileReq *CreateFileReq) SetName(name string, addrKR, nodeKR *crypto.KeyRing) error {
	clearTextName := crypto.NewPlainMessageFromString(name)

	encName, err := nodeKR.Encrypt(clearTextName, addrKR)
	if err != nil {
		return err
	}

	encNameString, err := encName.GetArmored()
	if err != nil {
		return err
	}

	createFileReq.Name = encNameString
	return nil
}

func (createFileReq *CreateFileReq) SetHash(name string, hashKey []byte) error {
	mac := hmac.New(sha256.New, hashKey)
	_, err := mac.Write([]byte(name))
	if err != nil {
		return err
	}

	createFileReq.Hash = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return nil
}

func (createFileReq *CreateFileReq) SetContentKeyPacketAndSignature(kr, addrKR *crypto.KeyRing) (*crypto.SessionKey, error) {
	newSessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, err
	}

	encSessionKey, err := kr.EncryptSessionKey(newSessionKey)
	if err != nil {
		return nil, err
	}

	sessionKeyPlainMessage := crypto.NewPlainMessage(newSessionKey.Key)
	sessionKeySignature, err := addrKR.SignDetached(sessionKeyPlainMessage)
	if err != nil {
		return nil, err
	}
	armoredSessionKeySignature, err := sessionKeySignature.GetArmored()
	if err != nil {
		return nil, err
	}

	createFileReq.ContentKeyPacket = base64.StdEncoding.EncodeToString(encSessionKey)
	createFileReq.ContentKeyPacketSignature = armoredSessionKeySignature
	return newSessionKey, nil
}

type CreateFileRes struct {
	ID         string // Encrypted Link ID
	RevisionID string // Encrypted Revision ID
}

type CreateRevisionRes struct {
	ID string // Encrypted Revision ID
}

type UpdateRevisionReq struct {
	BlockList         []BlockToken
	State             RevisionState
	ManifestSignature string
	SignatureAddress  string
	XAttr             string
}

type RevisionXAttrCommon struct {
	ModificationTime string
	Size             int64
}

type RevisionXAttr struct {
	Common RevisionXAttrCommon
}

func (updateRevisionReq *UpdateRevisionReq) SetEncXAttrString(addrKR, nodeKR *crypto.KeyRing, modificationTime time.Time, size int64) error {
	// Source
	// - https://github.com/ProtonMail/WebClients/blob/099a2451b51dea38b5f0e07ec3b8fcce07a88303/packages/shared/lib/interfaces/drive/link.ts#L53
	// - https://github.com/ProtonMail/WebClients/blob/main/applications/drive/src/app/store/_links/extendedAttributes.ts#L139
	// XAttr has following JSON structure encrypted by node key:
	// {
	//    Common: {
	//        ModificationTime: "2021-09-16T07:40:54+0000",
	//        Size: 13283,
	//    },
	// }
	jsonByteArr, err := json.Marshal(RevisionXAttr{
		Common: RevisionXAttrCommon{
			ModificationTime: modificationTime.Format("2006-01-02T15:04:05-0700"), /* ISO8601 */
			Size:             size,
		},
	})
	if err != nil {
		return err
	}

	encXattr, err := nodeKR.Encrypt(crypto.NewPlainMessage(jsonByteArr), addrKR)
	if err != nil {
		return err
	}

	encXattrString, err := encXattr.GetArmored()
	if err != nil {
		return err
	}

	updateRevisionReq.XAttr = encXattrString
	return nil
}

type BlockToken struct {
	Index int
	Token string
}
