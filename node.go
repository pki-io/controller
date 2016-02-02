package controller

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pki-io/core/config"
	"github.com/pki-io/core/document"
	"github.com/pki-io/core/index"
	"github.com/pki-io/core/node"
	"github.com/pki-io/core/ssh"
	"github.com/pki-io/core/x509"
	"os"
	"os/exec"
	"strings"
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

	logger.Debug("Generating node keys")
	if err := node.GenerateKeys(); err != nil {
		return nil, err
	}

	return node, nil
}

func (cont *NodeController) SecureSendPrivateToOrg(id, key string) error {
	return cont.SecureSendStringToOrg(cont.node.Dump(), id, key)
}

func (cont *NodeController) SecureSendStringToOrg(json, id, key string) error {
	logger.Debug("encrypting data for org")
	logger.Tracef("received json [NOT LOGGED] with pairing id '%s' and key [NOT LOGGED]", id)

	org := cont.env.controllers.org.org
	container, err := org.EncryptThenAuthenticateString(json, id, key)
	if err != nil {
		return err
	}

	logger.Debug("pushing container to org with id '%s'", org.Id())
	if err := cont.env.api.PushIncoming(org.Id(), "registration", container.Dump()); err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) CreateIndex() (*index.NodeIndex, error) {
	logger.Debug("creating node index")

	index, err := index.NewNode(nil)
	if err != nil {
		return nil, err
	}

	index.Data.Body.Id = x509.NewID()
	logger.Debugf("created index with id '%s'", index.Id())

	logger.Trace("returning index")
	return index, nil
}

func (cont *NodeController) SaveIndex(index *index.NodeIndex) error {

	logger.Debug("saving index")
	logger.Tracef("received index with id '%s'", index.Data.Body.Id)

	logger.Debug("encrypting and signing index for node")
	encryptedIndexContainer, err := cont.node.EncryptThenSignString(index.Dump(), nil)
	if err != nil {
		return err
	}

	logger.Debug("sending index")
	if err := cont.env.api.SendPrivate(cont.node.Id(), index.Data.Body.Id, encryptedIndexContainer.Dump()); err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) LoadConfig() error {
	logger.Debug("loading node config")
	var err error

	if cont.config == nil {
		logger.Debug("creating empty config")
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
		logger.Debugf("reading local file '%s'", NodeConfigFile)
		nodeConfig, err := cont.env.fs.local.Read(NodeConfigFile)
		if err != nil {
			return err
		}

		logger.Debug("loading config")
		if err := cont.config.Load(nodeConfig); err != nil {
			return err
		}
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) SaveConfig() error {
	logger.Debug("saving node config")

	logger.Debug("dumping config")
	cfgString, err := cont.config.Dump()
	if err != nil {
		return err
	}

	logger.Debugf("writing config to local file '%s'", NodeConfigFile)
	if err := cont.env.fs.local.Write(NodeConfigFile, cfgString); err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) GetNode(name string) (*node.Node, error) {
	logger.Debug("getting node")
	logger.Tracef("received name '%s'", name)

	org := cont.env.controllers.org.org

	index, err := cont.env.controllers.org.GetIndex()
	if err != nil {
		return nil, err
	}

	nodeId, err := index.GetNode(name)
	if err != nil {
		return nil, err
	}

	logger.Debugf("getting node '%s' from org", nodeId)
	nodeContainerJson, err := cont.env.api.GetPrivate(org.Id(), nodeId)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating new node container")
	nodeContainer, err := document.NewContainer(nodeContainerJson)
	if err != nil {
		return nil, err
	}

	logger.Debug("verifying and decrypting node container")
	nodeJson, err := org.VerifyThenDecrypt(nodeContainer)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating new node struct")
	n, err := node.New(nodeJson)
	if err != nil {
		return nil, err
	}

	logger.Trace("returning node")
	return n, nil
}

func (cont *NodeController) SaveNode() error {
	logger.Debug("saving node")
	id := cont.node.Data.Body.Id

	logger.Debugf("saving private node '%s' to home", id)
	if err := cont.env.fs.home.Write(id, cont.node.Dump()); err != nil {
		return err
	}

	return nil
}

func (cont *NodeController) ProcessNextCert() error {
	logger.Debug("processing next certificate")

	logger.Debug("getting next incoming certificate JSON")
	certContainerJson, err := cont.env.api.PopIncoming(cont.node.Data.Body.Id, "certs")
	if err != nil {
		return err
	}

	logger.Debug("creating certificate container from JSON")
	certContainer, err := document.NewContainer(certContainerJson)
	if err != nil {
		return err
	}

	logger.Debug("verifying container is signed by org")
	if err := cont.env.controllers.org.org.Verify(certContainer); err != nil {
		return err
	}

	logger.Debug("creating new certificate struct")
	cert, err := x509.NewCertificate(certContainer.Data.Body)
	if err != nil {
		return err
	}

	logger.Debugf("getting matching CSR for id '%s'", cert.Data.Body.Id)
	csrContainerJson, err := cont.env.api.GetPrivate(cont.node.Data.Body.Id, cert.Data.Body.Id)
	if err != nil {
		return err
	}

	logger.Debug("creating CSR container")
	csrContainer, err := document.NewContainer(csrContainerJson)
	if err != nil {
		return err
	}

	logger.Debug("verifying and decryping CSR container")
	csrJson, err := cont.node.VerifyThenDecrypt(csrContainer)
	if err != nil {
		return err
	}

	logger.Debug("creating CSR struct from JSON")
	csr, err := x509.NewCSR(csrJson)
	if err != nil {
		return err
	}

	logger.Debug("setting new ID for certificate")
	cert.Data.Body.Id = x509.NewID()

	logger.Debug("setting certificate private key from CSR")
	cert.Data.Body.PrivateKey = csr.Data.Body.PrivateKey

	logger.Debug("encrypting and signing certificate for node")
	updatedCertContainer, err := cont.node.EncryptThenSignString(cert.Dump(), nil)
	if err != nil {
		return err
	}

	logger.Debug("saving encrypted certificate for node")
	if err := cont.env.api.SendPrivate(cont.node.Data.Body.Id, cert.Data.Body.Id, updatedCertContainer.Dump()); err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) ProcessCerts() error {
	logger.Debug("processing node certificates")

	for {
		logger.Debug("getting number of incoming certificates")
		size, err := cont.env.api.IncomingSize(cont.node.Data.Body.Id, "certs")
		if err != nil {
			return err
		}
		logger.Debugf("found %d certificates to process", size)

		if size > 0 {
			if err := cont.ProcessNextCert(); err != nil {
				return err
			}
		} else {
			break
		}
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) CreateCSRs() error {
	logger.Debug("creating CSRs")

	logger.Debug("getting number of outgoing CSRs")
	numCSRs, err := cont.env.api.OutgoingSize(cont.node.Data.Body.Id, "csrs")
	if err != nil {
		return err
	}
	logger.Debugf("found '%d' CSRs", numCSRs)

	for i := 0; i < MinCSRs-numCSRs; i++ {
		if err := cont.NewCSR(); err != nil {
			return err
		}
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) NewCSR() error {
	logger.Debug("creating new CSR")

	csr, err := x509.NewCSR(nil)
	if err != nil {
		return err
	}

	csr.Data.Body.Id = x509.NewID()
	csr.Data.Body.Name = cont.node.Data.Body.Name
	subject := pkix.Name{CommonName: csr.Data.Body.Name}
	csr.Generate(&subject)

	logger.Debug("creating encrypted CSR container")
	csrContainer, err := cont.node.EncryptThenSignString(csr.Dump(), nil)
	if err != nil {
		return err
	}

	logger.Debug("saving node CSR")
	if err := cont.env.api.SendPrivate(cont.node.Data.Body.Id, csr.Data.Body.Id, csrContainer.Dump()); err != nil {
		return err
	}

	logger.Debug("getting public CSR")
	csrPublic, err := csr.Public()
	if err != nil {
		return err
	}

	logger.Debug("signing public CSR as node")
	csrPublicContainer, err := cont.node.SignString(csrPublic.Dump())
	if err != nil {
		return err
	}

	logger.Debug("putting public CSR in outgoing queue")
	if err := cont.env.api.PushOutgoing(cont.node.Data.Body.Id, "csrs", csrPublicContainer.Dump()); err != nil {
		return err
	}

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) Init(params *NodeParams) (*document.Container, error) {

	logger.Debug("initialising new node")

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := params.ValidateOrgId(true); err != nil {
		return nil, err
	}

	if err := cont.env.LoadLocalFs(); err != nil {
		return nil, err
	}

	if err := cont.env.LoadHomeFs(); err != nil {
		return nil, err
	}

	logger.Debugf("checking whether org directory '%s' exists", *params.OrgId)
	exists, err := cont.env.fs.local.Exists(*params.OrgId)
	if err != nil {
		return nil, err
	}

	if exists {
		return nil, fmt.Errorf("org directory '%s' already exists", *params.OrgId)
	}

	if err := cont.LoadConfig(); err != nil {
		return nil, err
	}

	if cont.config.OrgExists(*params.OrgId) {
		return nil, fmt.Errorf("org already exists: %s", *params.OrgId)
	}

	logger.Debugf("creating org directory '%s'", *params.OrgId)
	if err := cont.env.fs.local.CreateDirectory(*params.OrgId); err != nil {
		return nil, err
	}

	// Make all further fs calls relative to the Org
	logger.Debug("changing to org directory")
	if err := cont.env.fs.local.ChangeToDirectory(*params.OrgId); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAPI(); err != nil {
		return nil, err
	}

	cont.node, err = cont.CreateNode(*params.Name)
	if err != nil {
		return nil, err
	}

	if err := cont.SaveNode(); err != nil {
		return nil, err
	}

	index, err := cont.CreateIndex()
	if err != nil {
		return nil, err
	}

	cont.config.AddNode(cont.node.Data.Body.Name, cont.node.Data.Body.Id, index.Data.Body.Id, *params.OrgId)

	if err := cont.SaveConfig(); err != nil {
		return nil, err
	}

	if err := cont.CreateCSRs(); err != nil {
		return nil, err
	}

	if err := cont.SaveIndex(index); err != nil {
		return nil, err
	}

	logger.Debug("securing node data")
	container, err := cont.node.EncryptThenAuthenticateString(cont.node.DumpPublic(), *params.PairingId, *params.PairingKey)
	if err != nil {
		return nil, err
	}

	return container, nil
}

func (cont *NodeController) CreateLocalNode(name, pairingId, pairingKey string) (*node.Node, error) {
	var err error
	cont.node, err = cont.CreateNode(name)
	if err != nil {
		return nil, err
	}

	logger.Debugf("sending registration to org with pairing id '%s'", pairingId)
	if err := cont.SecureSendPrivateToOrg(pairingId, pairingKey); err != nil {
		return nil, err
	}

	index, err := cont.CreateIndex()
	if err != nil {
		return nil, err
	}

	if err := cont.LoadConfig(); err != nil {
		return nil, err
	}

	org := cont.env.controllers.org.org
	cont.config.AddNode(cont.node.Data.Body.Name, cont.node.Data.Body.Id, index.Data.Body.Id, org.Data.Body.Id)

	if err := cont.SaveConfig(); err != nil {
		return nil, err
	}

	if err := cont.CreateCSRs(); err != nil {
		return nil, err
	}

	if err := cont.SaveIndex(index); err != nil {
		return nil, err
	}

	return cont.node, nil
}

func (cont *NodeController) CreateRemoteNode(params *NodeParams) (*node.Node, error) {
	var err error

	s, err := ssh.Connect(*params.Host, strings.Split(*params.SSHOptions, " "))
	if err != nil {
		return nil, err
	}

	err = s.PutFiles("", *params.AgentFile, *params.InstallFile)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("sh", *params.AgentFile, *params.InstallFile)
	err = s.ExecuteCmd(cmd, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return nil, err
	}

	var registrationJson bytes.Buffer
	cmd = exec.Command("pki.io.id", "init", *params.Name, "--org-id", cont.env.controllers.org.org.Id(), "--pairing-id", *params.PairingId, "--pairing-key", *params.PairingKey)
	err = s.ExecuteCmd(cmd, nil, &registrationJson, os.Stderr)
	if err != nil {
		return nil, err
	}

	if err := cont.SecureSendStringToOrg(registrationJson.String(), *params.PairingId, *params.PairingKey); err != nil {
		return nil, err
	}

	return nil, nil // TODO
}

func (cont *NodeController) New(params *NodeParams) (*node.Node, error) {
	logger.Debug("creating new new")
	logger.Tracef("received params: %s", params)

	if err := params.ValidateName(true); err != nil {
		return nil, err
	}

	if err := params.ValidateHost(false); err != nil {
		return nil, err
	}

	if err := cont.env.LoadAdminEnv(); err != nil {
		return nil, err
	}

	if *params.Host == "" {
		if err := params.ValidatePairingId(true); err != nil {
			return nil, err
		}

		if err := params.ValidatePairingKey(true); err != nil {
			return nil, err
		}

		return cont.CreateLocalNode(*params.Name, *params.PairingId, *params.PairingKey)
	} else {

		if err := params.ValidateHost(true); err != nil {
			return nil, err
		}
		if err := params.ValidateAgentFile(true); err != nil {
			return nil, err
		}
		if err := params.ValidateInstallFile(true); err != nil {
			return nil, err
		}
		if err := params.ValidateSSHOptions(false); err != nil {
			return nil, err
		}

		return cont.CreateRemoteNode(params)
	}
}

func (cont *NodeController) Run(params *NodeParams) error {
	logger.Debug("running node tasks")
	logger.Tracef("received params: %s", params)

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

	logger.Trace("returning nil error")
	return nil
}

func (cont *NodeController) Cert(params *NodeParams) error {
	logger.Debug("getting certificates for node")
	logger.Tracef("received params: %s", params)
	return fmt.Errorf("not implemented")
}

func (cont *NodeController) List(params *NodeParams) ([]*node.Node, error) {
	logger.Debug("listing nodes")
	logger.Tracef("received params: %s", params)

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

	logger.Trace("returning nodes")
	return nodes, nil
}

func (cont *NodeController) Show(params *NodeParams) (*node.Node, error) {
	logger.Debug("showing node")
	logger.Tracef("received params: %s", params)
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

	logger.Trace("returning node")
	return cont.node, nil
}

func (cont *NodeController) Delete(params *NodeParams) error {
	logger.Debug("deleting node")
	logger.Tracef("received params: %s", params)
	return fmt.Errorf("Not implemented")
}
