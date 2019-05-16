"""
<Program Name>
  client.py

<Purpose>
  Provides common core functionality for Uptane clients:
  - Primary and Secondary clients will inherit client class
    and further implement additional functions as required
    by the clients

"""
from __future__ import print_function
from __future__ import unicode_literals

import uptane # Import before TUF modules; may change tuf.conf values.

import os # For paths and makedirs
import shutil # For copyfile
import random # for nonces
import zipfile # to expand the metadata archive retrieved from the Primary
import hashlib
import iso8601

import tuf.formats
import tuf.conf
import tuf.keys
import tuf.client.updater
import tuf.repository_tool as rt

import uptane.formats
import uptane.common
import uptane.services.director as director
import uptane.services.timeserver as timeserver
import uptane.encoding.asn1_codec as asn1_codec

from uptane.encoding.asn1_codec import DATATYPE_TIME_ATTESTATION
from uptane.encoding.asn1_codec import DATATYPE_ECU_MANIFEST
from uptane.encoding.asn1_codec import DATATYPE_VEHICLE_MANIFEST


log = uptane.logging.getLogger('client')
log.addHandler(uptane.file_handler)
log.addHandler(uptane.console_handler)
log.setLevel(uptane.logging.DEBUG)


class Client(object):

  """
  <Purpose>
    This class contains the necessary code to perform Uptane validation of
    images and metadata which is required by both Primary and Secondary clients.
    An implementation of Uptane should use code like this
    to perform full validation of images and metadata.

  <Fields>

    self.vin
      A unique identifier for the vehicle that contains the ECU.
      In this reference implementation, this conforms to
      uptane.formats.VIN_SCHEMA. There is no need to use the vehicle's VIN in
      particular; we simply need a unique identifier for the vehicle, known
      to the Director.

    self.ecu_serial
      A unique identifier for the ECU. In this reference implementation,
      this conforms to uptane.formats.ECU_SERIAL_SCHEMA.
      (In other implementations, the important point is that this should be
      unique.) The Director should be aware of this identifier.

    self.ecu_key:
      The signing key for the ECU. This key will be used to sign
      Vehicle Manifests(by Primary ECU) or ECU Manifests(by Secondary ECU)
      that will then be sent along to the Primary (and subsequently
      to the Director). The Director should be aware of the corresponding
      public key, so that it can validate these ECU Manifests.
      Conforms to tuf.formats.ANYKEY_SCHEMA.

    self.updater:
      A tuf.client.updater.Updater object used to retrieve metadata and
      target files from the Director and Image repositories.

    self.full_client_dir:
      The full path of the directory where all client data is stored for the
      ECU. This includes verified and unverified metadata and images and
      any temp files. Conforms to tuf.formats.PATH_SCHEMA.

    self.director_repo_name
      The name of the Director repository (e.g. 'director'), as listed in the
      map (or pinning) file (pinned.json). This value must appear in that file.
      Used to distinguish between the Image Repository and the Director
      Repository. Conforms to tuf.formats.REPOSITORY_NAME_SCHEMA.

    self.timeserver_public_key:
      The public key of the Timeserver, which will be used to validate signed
      time attestations from the Timeserver.
      Conforms to tuf.formats.ANYKEY_SCHEMA.

    self.all_valid_timeserver_times:
      A list of all times extracted from all Timeserver attestations that have
      been verified by update_time.
      Items are appended to the end.

  Methods, as called: ("self" arguments excluded):

    __init__(...)

  """

  def __init__(
    self,
    full_client_dir,
    director_repo_name,
    vin,
    ecu_serial,
    ecu_key,
    time,
    timeserver_public_key):
    """
      <Purpose>
        Constructor for class Client

      <Arguments>

        full_client_dir       See class docstring above.

        director_repo_name    See class docstring above.

        vin                   See class docstring above.

        ecu_serial            See class docstring above.

        primary_key           See class docstring above.

        timeserver_public_key See class docstring above.

        time
          An initial time to set the Primary's "clock" to, conforming to
          tuf.formats.ISO8601_DATETIME_SCHEMA.


      <Exceptions>

        tuf.FormatError
          if the arguments are not correctly formatted

        uptane.Error
          if director_repo_name is not a known repository based on the
          map/pinning file (pinned.json)

      <Side Effects>
        None.
       """

    # Check arguments:
    tuf.formats.PATH_SCHEMA.check_match(full_client_dir)
    tuf.formats.PATH_SCHEMA.check_match(director_repo_name)
    uptane.formats.VIN_SCHEMA.check_match(vin)
    uptane.formats.ECU_SERIAL_SCHEMA.check_match(ecu_serial)
    tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(time)
    tuf.formats.ANYKEY_SCHEMA.check_match(timeserver_public_key)
    tuf.formats.ANYKEY_SCHEMA.check_match(ecu_key)

    self.director_repo_name = director_repo_name
    self.ecu_key = ecu_key
    self.vin = vin
    self.ecu_serial = ecu_serial
    self.full_client_dir = full_client_dir
    self.timeserver_public_key = timeserver_public_key
    self.validated_targets = []

    # Create a TAP-4-compliant updater object. This will read pinned.json
    # and create single-repository updaters within it to handle connections to
    # each repository.
    self.updater = tuf.client.updater.Updater('updater')

    if director_repo_name not in self.updater.pinned_metadata['repositories']:
      raise uptane.Error('Given name for the Director repository is not a '
                         'known repository, according to the pinned metadata from pinned.json')





  def refresh_toplevel_metadata(self):
    """
    Refreshes client's metadata for the top-level roles:
      root, targets, snapshot, and timestamp

    See tuf.client.updater.Updater.refresh() for details, or the
    Uptane Standard, section 5.4.4.2 (Full Verification).

     This can raise TUF update exceptions like
      - tuf.ExpiredMetadataError:
          if after attempts to update the Root metadata succeeded or failed,
          whatever currently trusted Root metadata we ended up with was expired.
      - tuf.NoWorkingMirrorError:
          if we could not obtain and verify all necessary metadata
    """

    # Refresh the Director first, per the Uptane Standard.
    self.updater.refresh(repo_name=self.director_repo_name)

    # Now that we've dealt with the Director repository, deal with any and all
    # other repositories, presumably Image Repositories.
    for repository_name in self.updater.repositories:
      if repository_name == self.director_repo_name:
        continue

      self.updater.refresh(repo_name=repository_name)





  def get_validated_target_info(self, target_filepath):
    """
    (Could be called: get Director's version of the fully validated target info)

    <Purpose>

      Returns trustworthy target information for the given target file
      (specified by its file path), from the Director, validated against the
      Image Repository (or whichever repositories are required per the
      pinned.json file).

      The returned information has been cleared according to the trust
      requirements of the pinning file (pinned.json) that this client is
      equipped with. Assuming typical pinned.json configuration for Uptane,
      this means that there is a multi-repository delegation to [the Director
      Repository plus the Image Repository]. The target file info received
      within this method is that from all repositories in the multi-repository
      delegation, and each is guaranteed to be identical to the others in all
      respects (e.g. crytographic hash and length) except for the "custom"
      metadata field, since the Director includes an additional piece of
      information in the fileinfo: the ECU Serial to which the target file is
      assigned.

      This method returns only the Director's version of this target file info,
      which includes that "custom" field with ECU Serial assignments.

    <Returns>
      Target file info compliant with tuf.formats.TARGETFILE_INFO_SCHEMA,


    <Exceptions>

      tuf.UnknownTargetError
        if a given filepath is not listed by the consensus of Director and
        Image Repository (or through whichever trusted path is specified by
        this client's pinned.json file.) If info is returned, it will match
        tuf.formats.TARGETFILE_SCHEMA and will have been validated by all
        required parties.

      tuf.NoWorkingMirrorError
        will be raised by the updater.target() call here if we are unable to
        validate reliable target info for the target file specified (if the
        repositories do not agree, or we could not reach them, or so on).

      uptane.Error
        if the Director targets file has not provided information about the
        given target_filepath, but target_filepath has nevertheless been
        validated. This could happen if the map/pinning file for some reason
        incorrectly set to not require metadata from the Director.

    """
    tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)

    validated_target_info = self.updater.target(
      target_filepath, multi_custom=True)

    # validated_target_info will now look something like this:
    # {
    #   'Director': {
    #     filepath: 'django/django.1.9.3.tgz',
    #     fileinfo: {hashes: ..., length: ..., custom: {'ecu_serial': 'ECU1010101'} } },
    #   'ImageRepo': {
    #     filepath: 'django/django.1.9.3.tgz',
    #     fileinfo: {hashes: ..., length: ... } } }
    # }

    # We expect there to be an entry in the dict with key name equal to the
    # name of the Director repository (specified in pinned.json).

    if self.director_repo_name not in validated_target_info:
      # TODO: Consider a different exception class. This seems more like an
      # assert statement, though.... If this happens, something is wrong in
      # code, or pinned.json is misconfigured (to allow target validation
      # whereby the Director is not specified in some multi-repository
      # delegations) or the value of director_repo_name passed to the
      # initialization of this object was wrong. Those are the edge cases I can
      # come up with that could cause this.

      # If the Director repo specified as self.director_repo_name is not in
      # pinned.json at all, we'd have thrown an error during __init__. If the
      # repos couldn't provide validated target file info, we'd have caught an
      # error earlier instead.

      raise uptane.Error('Unexpected behavior: did not receive target info from'
                         ' Director repository (' + repr(self.director_repo_name) + ') for '
                                                                                    'a target (' + repr(
        target_filepath) + '). Is pinned.json configured '
                           'to allow some targets to validate without Director approval, or is'
                           'the wrong repository specified as the Director repository in the '
                           'initialization of this primary object?')

    # Defensive coding: this should already have been checked.
    tuf.formats.TARGETFILE_SCHEMA.check_match(
      validated_target_info[self.director_repo_name])

    return validated_target_info[self.director_repo_name]





  def get_target_list_from_director(self):
    """
    This method extracts the Director's instructions from the targets role in
    the Director repository's metadata. These must still be validated against
    the Image Repository in further calls.
    """
    # TODO: This will have to be changed (along with the functions that depend
    # on this function's output) once multi-role delegations can yield multiple
    # targetfile_info objects. (Currently, we only yield more than one at the
    # multi-repository delegation level.)

    # Refresh the top-level metadata first (all repositories).
    log.debug('Refreshing top level metadata from all repositories.')

    # Refresh the top-level metadata first (all repositories).
    self.refresh_toplevel_metadata()

    directed_targets = self.updater.targets_of_role(
      rolename='targets', repo_name=self.director_repo_name)

    if not directed_targets:
      log.info('A correctly signed statement from the Director indicates that '
          'this vehicle has NO updates to install.')
    else:
      log.info('A correctly signed statement from the Director indicates that '
          'this vehicle has updates to install:' +
          repr([targ['filepath'] for targ in directed_targets]))

    return directed_targets





  def verify_timeserver_signature(self, timeserver_attestation):
    """
    The response from the Timeserver should then be provided to this function.
    This function attempts to verify the given attestation,
    if timeserver_attestation is correctly signed by the expected Timeserver

    If the client is using ASN.1/DER metadata, then timeserver_attestation is
    expected to be in that format, as a byte string.
    Otherwise, we're using simple Python dictionaries and timeserver_attestation
    conforms to uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.
    """
    # If we're using ASN.1/DER format, convert the attestation into something
    # comprehensible (JSON-compatible dictionary) instead.
    if tuf.conf.METADATA_FORMAT == 'der':
      timeserver_attestation = asn1_codec.convert_signed_der_to_dersigned_json(
        timeserver_attestation, DATATYPE_TIME_ATTESTATION)

    # Check format.
    uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.check_match(
      timeserver_attestation)

    # Assume there's only one signature. This assumption is made for simplicity
    # in this reference implementation. If the Timeserver needs to sign with
    # multiple keys for some reason, that can be accomodated.
    assert len(timeserver_attestation['signatures']) == 1

    verified = uptane.common.verify_signature_over_metadata(
      self.timeserver_public_key,
      timeserver_attestation['signatures'][0],
      timeserver_attestation['signed'],
      DATATYPE_TIME_ATTESTATION)

    if not verified:
      raise tuf.BadSignatureError('Timeserver returned an invalid signature. '
                                  'Time is questionable, so not saved. If you see this persistently, '
                                  'it is possible that there is a Man in the Middle attack underway.')
