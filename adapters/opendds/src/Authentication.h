#ifndef OPENDDS_PQSEC_AUTHENTICATION_H
#define OPENDDS_PQSEC_AUTHENTICATION_H

#include "Crypto.h"

#include <dds/DdsSecurityCoreC.h>
#include <dds/DCPS/GuidUtils.h>
#include <dds/DCPS/security/Authentication/LocalAuthCredentialData.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace OpenDDS_PQSec {

class Authentication : public virtual DDS::Security::Authentication {
public:
  Authentication();
  virtual ~Authentication();

  DDS::Security::ValidationResult_t validate_local_identity(
    DDS::Security::IdentityHandle&, OpenDDS::DCPS::GUID_t&, DDS::Security::DomainId_t,
    const DDS::DomainParticipantQos&, const OpenDDS::DCPS::GUID_t&,
    DDS::Security::SecurityException&);
  CORBA::Boolean get_identity_token(DDS::Security::IdentityToken&,
    DDS::Security::IdentityHandle, DDS::Security::SecurityException&);
  CORBA::Boolean get_identity_status_token(DDS::Security::IdentityStatusToken&,
    DDS::Security::IdentityHandle, DDS::Security::SecurityException&);
  CORBA::Boolean set_permissions_credential_and_token(DDS::Security::IdentityHandle,
    const DDS::Security::PermissionsCredentialToken&, const DDS::Security::PermissionsToken&,
    DDS::Security::SecurityException&);
  DDS::Security::ValidationResult_t validate_remote_identity(
    DDS::Security::IdentityHandle&, DDS::Security::AuthRequestMessageToken&,
    const DDS::Security::AuthRequestMessageToken&, DDS::Security::IdentityHandle,
    const DDS::Security::IdentityToken&, const OpenDDS::DCPS::GUID_t&,
    DDS::Security::SecurityException&);
  DDS::Security::ValidationResult_t begin_handshake_request(
    DDS::Security::HandshakeHandle&, DDS::Security::HandshakeMessageToken&,
    DDS::Security::IdentityHandle, DDS::Security::IdentityHandle,
    const DDS::OctetSeq&, DDS::Security::SecurityException&);
  DDS::Security::ValidationResult_t begin_handshake_reply(
    DDS::Security::HandshakeHandle&, DDS::Security::HandshakeMessageToken&,
    DDS::Security::IdentityHandle, DDS::Security::IdentityHandle,
    const DDS::OctetSeq&, DDS::Security::SecurityException&);
  DDS::Security::ValidationResult_t process_handshake(
    DDS::Security::HandshakeMessageToken&, const DDS::Security::HandshakeMessageToken&,
    DDS::Security::HandshakeHandle, DDS::Security::SecurityException&);
  DDS::Security::SharedSecretHandle* get_shared_secret(
    DDS::Security::HandshakeHandle, DDS::Security::SecurityException&);
  CORBA::Boolean get_authenticated_peer_credential_token(
    DDS::Security::AuthenticatedPeerCredentialToken&, DDS::Security::HandshakeHandle,
    DDS::Security::SecurityException&);
  CORBA::Boolean set_listener(DDS::Security::AuthenticationListener_ptr,
    DDS::Security::SecurityException&);
  CORBA::Boolean return_identity_token(const DDS::Security::IdentityToken&,
    DDS::Security::SecurityException&);
  CORBA::Boolean return_identity_status_token(const DDS::Security::IdentityStatusToken&,
    DDS::Security::SecurityException&);
  CORBA::Boolean return_authenticated_peer_credential_token(
    const DDS::Security::AuthenticatedPeerCredentialToken&, DDS::Security::SecurityException&);
  CORBA::Boolean return_handshake_handle(DDS::Security::HandshakeHandle,
    DDS::Security::SecurityException&);
  CORBA::Boolean return_identity_handle(DDS::Security::IdentityHandle,
    DDS::Security::SecurityException&);
  CORBA::Boolean return_sharedsecret_handle(DDS::Security::SharedSecretHandle*,
    DDS::Security::SecurityException&);

private:
  struct LocalIdentity;
  struct RemoteIdentity;
  struct Handshake;
  typedef std::shared_ptr<LocalIdentity> LocalPtr;
  typedef std::shared_ptr<RemoteIdentity> RemotePtr;
  typedef std::shared_ptr<Handshake> HandshakePtr;

  CORBA::Long next_handle();
  LocalPtr local(DDS::Security::IdentityHandle) const;
  RemotePtr remote(DDS::Security::IdentityHandle) const;
  bool validate_remote_credentials(Handshake&, const DDS::Security::Token&,
    DDS::OctetSeq&, DDS::Security::SecurityException&);

  mutable std::mutex mutex_;
  CORBA::Long next_handle_;
  std::map<DDS::Security::IdentityHandle, LocalPtr> locals_;
  std::map<DDS::Security::IdentityHandle, RemotePtr> remotes_;
  std::map<DDS::Security::HandshakeHandle, HandshakePtr> handshakes_;
  DDS::Security::AuthenticationListener_var listener_;
};

} // namespace OpenDDS_PQSec

#endif
