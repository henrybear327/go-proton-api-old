package proton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

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

func (createFileReq *CreateFileReq) SetContentKeyPacketAndSignature(kr, addrKR *crypto.KeyRing) error {
	newSessionKey, err := crypto.GenerateSessionKey()
	if err != nil {
		return err
	}

	encSessionKey, err := kr.EncryptSessionKey(newSessionKey)
	if err != nil {
		return err
	}

	sessionKeyPlainMessage := crypto.NewPlainMessage(newSessionKey.Key)
	sessionKeySignature, err := addrKR.SignDetached(sessionKeyPlainMessage)
	if err != nil {
		return err
	}
	armoredSessionKeySignature, err := sessionKeySignature.GetArmored()
	if err != nil {
		return err
	}

	createFileReq.ContentKeyPacket = base64.StdEncoding.EncodeToString(encSessionKey)
	createFileReq.ContentKeyPacketSignature = armoredSessionKeySignature
	return nil
}

type CreateFileRes struct {
	ID         string // Encrypted Link ID
	RevisionID string // Encrypted Revision ID
}

type UpdateRevisionReq struct {
	BlockList         []BlockToken
	State             RevisionState
	ManifestSignature string
	SignatureAddress  string
}

type BlockToken struct {
	Index int
	Token string
}
