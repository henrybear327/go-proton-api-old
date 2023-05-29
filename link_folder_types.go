package proton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type CreateFolderReq struct {
	ParentLinkID string

	Name string
	Hash string

	NodeKey     string
	NodeHashKey string

	NodePassphrase          string
	NodePassphraseSignature string

	SignatureAddress string
}

func (createFolderReq *CreateFolderReq) SetName(name string, addrKR, nodeKR *crypto.KeyRing) error {
	clearTextName := crypto.NewPlainMessageFromString(name)

	encName, err := nodeKR.Encrypt(clearTextName, addrKR)
	if err != nil {
		return err
	}

	encNameString, err := encName.GetArmored()
	if err != nil {
		return err
	}

	createFolderReq.Name = encNameString
	return nil
}

func (createFolderReq *CreateFolderReq) SetHash(name string, hashKey []byte) error {
	mac := hmac.New(sha256.New, hashKey)
	_, err := mac.Write([]byte(name))
	if err != nil {
		return err
	}

	createFolderReq.Hash = hex.EncodeToString(mac.Sum(nil))
	return nil
}

func (createFolderReq *CreateFolderReq) SetNodeHashKey(parentNodeKey *crypto.KeyRing) error {
	token, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}

	tokenMessage := crypto.NewPlainMessage(token)

	encToken, err := parentNodeKey.Encrypt(tokenMessage, parentNodeKey)
	if err != nil {
		return err
	}

	nodeHashKey, err := encToken.GetArmored()
	if err != nil {
		return err
	}

	createFolderReq.NodeHashKey = nodeHashKey

	return nil
}

type CreateFolderRes struct {
	ID string // Encrypted Link ID
}
