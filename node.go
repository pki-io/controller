// ThreatSpec package controller
package controller

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/pki-io/core/config"
	"github.com/pki-io/core/document"
	"github.com/pki-io/core/index"
	"github.com/pki-io/core/node"
	"github.com/pki-io/core/x509"
)

const (
	NodeConfigFile string = "node.conf"
	MinCSRs        int    = 5
)

type NodeController struct {
	env    *Environment
	config *config.NodeConfig
	node   *node.Node
}

func NewNode(env *Environment) (*NodeController, error) {
	cont := new(NodeController)
	cont.env = env
	return cont, nil
}

func (cont *NodeController) CreateNode(name string) (*node.Node, error) {
	node, err := node.New(nil)
	if err != nil {
		return nil, err
	}

	node.Data.Body.Name = name
	node.Data.Body.Id = x509.NewID()

	cont.env.logger.Debug("Generating node keys")
	if err := node.GenerateKeys(); err != nil {
		return nil, err
	}

	return node, nil
}

func (cont *NodeController) SecureSendPrivateToOrg(id, key string) error {
	return cont.SecureSendStringToOrg(cont.node.Dump(), id, key)
}

func (cont *NodeController) SecureSendStringToOrg(json, id, key string) error {
	cont.env.logger.Debug("encrypting data for org")
	cont.env.logger.Tracef("received json [NOT LOGGED] with pairing id '%s' and key [NOT LOGGED]", id)

	org := cont.env.controllers.org.org
	container, err := org.EncryptThenAuthenticateString(json, id, key)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("pushing container to org with id '%s'", org.Id())
	if err := cont.env.api.PushIncoming(org.Id(), "registration", container.Dump()); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) CreateIndex() (*index.NodeIndex, error) {
	cont.env.logger.Debug("creating node index")

	index, err := index.NewNode(nil)
	if err != nil {
		return nil, err
	}

	index.Data.Body.Id = x509.NewID()
	cont.env.logger.Debug("created index with id '%s'", index.Id())

	cont.env.logger.Trace("returning index")
	return index, nil
}

func (cont *NodeController) SaveIndex(index *index.NodeIndex) error {
	cont.env.logger.Debug("saving index")
	cont.env.logger.Tracef("received inded with id '%s'", index.Data.Body.Id)
	org := cont.env.controllers.org.org

	cont.env.logger.Debug("encrypting and signing index for org")
	encryptedIndexContainer, err := org.EncryptThenSignString(index.Dump(), nil)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("sending index to org")
	if err := cont.env.api.SendPrivate(org.Id(), index.Data.Body.Id, encryptedIndexContainer.Dump()); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) LoadConfig() error {
	cont.env.logger.Debug("loading node config")
	var err error

	if cont.config == nil {
		cont.env.logger.Debug("creating empty config")
		cont.config, err = config.NewNode()
		if err != nil {
			return err
		}
	}

	exists, err := cont.env.fs.local.Exists(NodeConfigFile)
	if err != nil {
		return err
	}

	if exists {
		cont.env.logger.Debugf("reading local file '%s'", NodeConfigFile)
		nodeConfig, err := cont.env.fs.local.Read(NodeConfigFile)
		if err != nil {
			return err
		}

		cont.env.logger.Debug("loading config")
		if err := cont.config.Load(nodeConfig); err != nil {
			return err
		}
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) SaveConfig() error {
	cont.env.logger.Debug("saving node config")

	cont.env.logger.Debug("dumping config")
	cfgString, err := cont.config.Dump()
	if err != nil {
		return err
	}

	cont.env.logger.Debugf("writing config to local file '%s'", NodeConfigFile)
	if err := cont.env.fs.local.Write(NodeConfigFile, cfgString); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) GetNode(name string) (*node.Node, error) {
	cont.env.logger.Debug("getting node")
	cont.env.logger.Tracef("received name '%s'", name)

	org := cont.env.controllers.org.org

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	nodeId, err := index.GetNode(name)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Debugf("getting node '%s' from org", nodeId)
	nodeContainerJson, err := cont.env.api.GetPrivate(org.Id(), nodeId)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Debug("creating new node container")
	nodeContainer, err := document.NewContainer(nodeContainerJson)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Debug("verifying and decrypting node container")
	nodeJson, err := org.VerifyThenDecrypt(nodeContainer)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Debug("creating new node struct")
	n, err := node.New(nodeJson)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Trace("returning node")
	return n, nil
}

func (cont *NodeController) ProcessNextCert() error {
	cont.env.logger.Debug("processing next certificate")

	cont.env.logger.Debug("getting next incoming certificate JSON")
	certContainerJson, err := cont.env.api.PopIncoming(cont.node.Data.Body.Id, "certs")
	if err != nil {
		return err
	}

	cont.env.logger.Debug("creating certificate container from JSON")
	certContainer, err := document.NewContainer(certContainerJson)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("verifying container is signed by org")
	if err := cont.env.controllers.org.org.Verify(certContainer); err != nil {
		return err
	}

	cont.env.logger.Debug("creating new certificate struct")
	cert, err := x509.NewCertificate(certContainer.Data.Body)
	if err != nil {
		return err
	}

	cont.env.logger.Debugf("getting matching CSR for id '%s'", cert.Data.Body.Id)
	csrContainerJson, err := cont.env.api.GetPrivate(cont.node.Data.Body.Id, cert.Data.Body.Id)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("creating CSR container")
	csrContainer, err := document.NewContainer(csrContainerJson)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("verifying and decryping CSR container")
	csrJson, err := cont.node.VerifyThenDecrypt(csrContainer)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("creating CSR struct from JSON")
	csr, err := x509.NewCSR(csrJson)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("setting new ID for certificate")
	cert.Data.Body.Id = x509.NewID()

	cont.env.logger.Debug("setting certificate private key from CSR")
	cert.Data.Body.PrivateKey = csr.Data.Body.PrivateKey

	cont.env.logger.Debug("encrypting and signing certificate for node")
	updatedCertContainer, err := cont.node.EncryptThenSignString(cert.Dump(), nil)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("saving encrypted certificate for node")
	if err := cont.env.api.SendPrivate(cont.node.Data.Body.Id, cert.Data.Body.Id, updatedCertContainer.Dump()); err != nil {
		return err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return err
	}

	if err := index.AddCertTags(cert.Data.Body.Id, cert.Data.Body.Tags); err != nil {
		return err
	}

	if err := cont.env.controllers.org.SaveIndex(index); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) ProcessCerts() error {
	cont.env.logger.Debug("processing node certificates")

	for {
		cont.env.logger.Debug("getting number of incoming certificates")
		size, err := cont.env.api.IncomingSize(cont.node.Data.Body.Id, "certs")
		if err != nil {
			return err
		}
		cont.env.logger.Debugf("found %d certificates to process", size)

		if size > 0 {
			if err := cont.ProcessNextCert(); err != nil {
				return err
			}
		} else {
			break
		}
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) CreateCSRs() error {
	cont.env.logger.Debug("creating CSRs")

	cont.env.logger.Debug("getting number of outgoing CSRs")
	numCSRs, err := cont.env.api.OutgoingSize(cont.node.Data.Body.Id, "csrs")
	if err != nil {
		return err
	}
	cont.env.logger.Debugf("found '%d' CSRs", numCSRs)

	for i := 0; i < MinCSRs-numCSRs; i++ {
		if err := cont.NewCSR(); err != nil {
			return err
		}
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) NewCSR() error {
	cont.env.logger.Debug("creating new CSR")

	csr, err := x509.NewCSR(nil)
	if err != nil {
		return err
	}

	csr.Data.Body.Id = x509.NewID()
	csr.Data.Body.Name = cont.node.Data.Body.Name
	subject := pkix.Name{CommonName: csr.Data.Body.Name}
	csr.Generate(&subject)

	cont.env.logger.Debug("creating encrypted CSR container")
	csrContainer, err := cont.node.EncryptThenSignString(csr.Dump(), nil)
	if err != nil {
		return err
	}

	cont.env.logger.Debug("saving node CSR")
	if err := cont.env.api.SendPrivate(cont.node.Data.Body.Id, csr.Data.Body.Id, csrContainer.Dump()); err != nil {
		return err
	}

	cont.env.logger.Debug("getting public CSR")
	csrPublic, err := csr.Public()
	if err != nil {
		return err
	}

	cont.env.logger.Debug("signing public CSR as node")
	csrPublicContainer, err := cont.node.SignString(csrPublic.Dump())
	if err != nil {
		return err
	}

	cont.env.logger.Debug("putting public CSR in outgoing queue")
	if err := cont.env.api.PushOutgoing(cont.node.Data.Body.Id, "csrs", csrPublicContainer.Dump()); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) New(params *NodeParams) (*node.Node, error) {
	cont.env.logger.Debug("creating new new")
	cont.env.logger.Tracef("received params: %s", params)
	var err error

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	cont.node, err = cont.CreateNode(*params.Name)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Debugf("sending registration to org with pairing id '%s'", *params.PairingId)
	if err := cont.SecureSendPrivateToOrg(*params.PairingId, *params.PairingKey); err != nil {
		return nil, err
	}

	index, err := cont.CreateIndex()
	if err != nil {
		return nil, err
	}

	if err := cont.LoadConfig(); err != nil {
		return nil, err
	}

	cont.config.AddNode(cont.node.Data.Body.Name, cont.node.Data.Body.Id, index.Data.Body.Id)

	if err := cont.SaveConfig(); err != nil {
		return nil, err
	}

	if err := cont.CreateCSRs(); err != nil {
		return nil, err
	}

	if err := cont.SaveIndex(index); err != nil {
		return nil, err
	}

	cont.env.logger.Trace("returning node")
	return cont.node, nil
}

func (cont *NodeController) Run(params *NodeParams) error {
	cont.env.logger.Debug("running node tasks")
	cont.env.logger.Tracef("received params: %s", params)

	var err error

	if err := params.ValidateName(true); err != nil {
		return err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return err
	}

	cont.node, err = cont.GetNode(*params.Name)
	if err != nil {
		return err
	}

	if err := cont.ProcessCerts(); err != nil {
		return err
	}

	cont.env.logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) Cert(params *NodeParams) error {
	cont.env.logger.Debug("getting certificates for node")
	cont.env.logger.Tracef("received params: %s", params)
	return fmt.Errorf("not implemented")
}

func (cont *NodeController) List(params *NodeParams) ([]*node.Node, error) {
	cont.env.logger.Debug("listing nodes")
	cont.env.logger.Tracef("received params: %s", params)

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	nodes := make([]*node.Node, 0)
	for name, _ := range index.GetNodes() {
		node, err := cont.GetNode(name)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	cont.env.logger.Trace("returning nodes")
	return nodes, nil
}

func (cont *NodeController) Show(params *NodeParams) (*node.Node, error) {
	cont.env.logger.Debug("showing node")
	cont.env.logger.Tracef("received params: %s", params)
	var err error

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	cont.node, err = cont.GetNode(*params.Name)
	if err != nil {
		return nil, err
	}

	cont.env.logger.Trace("returning node")
	return cont.node, nil
}

func (cont *NodeController) Delete(params *NodeParams) error {
	cont.env.logger.Debug("deleting node")
	cont.env.logger.Tracef("received params: %s", params)
	return fmt.Errorf("Not implemented")
}
