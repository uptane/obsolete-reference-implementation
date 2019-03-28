"""
<Program Name>
  secondary.py

<Purpose>
  Provides core functionality for Uptane Secondary ECU clients:
  - Given an archive of metadata and an image file, performs full verification
    of both, employing TUF (The Update Framework), determining if this
    Secondary ECU has been instructed to install the image by the Director and
    if the image is also valid per the Image Repository.
  - Generates ECU Manifests describing the state of the Secondary for Director
    perusal
  - Generates nonces for time requests from the Timeserver, and validates
    signed times provided by the Timeserver, maintaining trustworthy times.
    Rotates nonces after they have appeared in Timeserver responses.

  A detailed explanation of the role of the Secondary in Uptane is available in
  the "Design Overview" and "Implementation Specification" documents, links to
  which are maintained at uptane.github.io
"""
from __future__ import print_function
from __future__ import unicode_literals
from io import open # TODO: Determine if this should be here.

import uptane # Import before TUF modules; may change tuf.conf values.

import os # For paths and makedirs
import shutil # For copyfile
import random # for nonces
import zipfile # to expand the metadata archive retrieved from the Primary
import hashlib
import iso8601
import time

import tuf.formats
import tuf.keys
import tuf.client.updater
import tuf.repository_tool as rt

import uptane.formats
import uptane.common
import uptane.encoding.asn1_codec as asn1_codec

from uptane.encoding.asn1_codec import DATATYPE_TIME_ATTESTATION
from uptane.encoding.asn1_codec import DATATYPE_ECU_MANIFEST
from uptane.encoding.asn1_codec import DATATYPE_VEHICLE_MANIFEST

from uptane import GREEN, RED, YELLOW, ENDCOLORS


log = uptane.logging.getLogger('secondary')
log.addHandler(uptane.file_handler)
log.addHandler(uptane.console_handler)
log.setLevel(uptane.logging.DEBUG)



class Secondary(object):

  """
  <Purpose>
    This class contains the necessary code to perform Uptane validation of
    images and metadata. An implementation of Uptane should use code like this
    to perform full validation of images and metadata.

  <Fields>

    self.vin
      A unique identifier for the vehicle that contains this Secondary ECU.
      In this reference implementation, this conforms to
      uptane.formats.VIN_SCHEMA. There is no need to use the vehicle's VIN in
      particular; we simply need a unique identifier for the vehicle, known
      to the Director.

    self.ecu_serial
      A unique identifier for this Secondary ECU. In this reference
      implementation, this conforms to uptane.formats.ECU_SERIAL_SCHEMA.
      (In other implementations, the important point is that this should be
      unique.) The Director should be aware of this identifier.

    self.ecu_key:
      The signing key for this Secondary ECU. This key will be used to sign
      ECU Manifests that will then be sent along to the Primary (and
      subsequently to the Director). The Director should be aware of the
      corresponding public key, so that it can validate these ECU Manifests.
      Conforms to tuf.formats.ANYKEY_SCHEMA.

    self.updater:
      A tuf.client.updater.Updater object used to retrieve metadata and
      target files from the Director and Image repositories.

    self.full_client_dir:
      The full path of the directory where all client data is stored for this
      secondary. This includes verified and unverified metadata and images and
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

    self.partial_verifying:
      False if this client is to employ full metadata verification (the default)
      with all checks included in the Uptane Implementation Specification,
      else True if this instance is a partial verifier.
      A Partial Verification Secondary is programmed with the Director's
      Targets role public key and will only validate that signature on that
      file, leaving it susceptible to some attacks if the Director key
      is compromised or has to change.

    self.director_public_key
      If this is a partial verification secondary, we store the key that we
      expect the Director to use here. Full verification clients should have
      None in this field. If provided, this conforms to
      tuf.formats.ANYKEY_SCHEMA.

    self.firmware_fileinfo:
      The target file info for the image this Secondary ECU is currently using
      (has currently "installed"). This is generally filename, hash, and
      length. See tuf.formats.TARGETFILE_SCHEMA, which contains
      tuf.formats.FILEINFO_SCHEMA. This info is provided in ECU Manifests
      generated for the Director's consumption.

    self.nonce_next
      Next nonce the ECU will send to the Timeserver (via the Primary).

    self.last_nonce_sent
      The latest nonce this ECU sent to the Timeserver (via the Primary).

    self.all_valid_timeserver_times:
      A list of all times extracted from all Timeserver attestations that have
      been verified by update_time.
      Items are appended to the end.

    self.validated_targets_for_this_ecu:
      A list of the targets validated for this ECU, populated in method
      fully_validate_metadata (which is called by method process_metadata).
      # TODO: Since this is now expected to always be one target, this should
      # just be a single value rather than a list....


  Methods, as called: ("self" arguments excluded):

    __init__(...)

    Nonce handling:
      set_nonce_as_sent()
      change_nonce()
      _create_nonce()

    Manifest handling:
      generate_signed_ecu_manifest()

    Metadata handling and verification of metadata and data
      update_time(timeserver_attestation)
      process_metadata(metadata_archive_fname)
      _expand_metadata_archive(metadata_archive_fname)
      fully_validate_metadata()
      get_validated_target_info(target_filepath)
      validate_image(image_fname)



  """

  def __init__(
    self,
    full_client_dir,
    director_repo_name,
    vin,
    ecu_serial,
    ecu_key,
    time,
    timeserver_public_key,
    firmware_fileinfo=None,
    director_public_key=None,
    partial_verifying=False):

    """
    <Purpose>
      Constructor for class Secondary

    <Arguments>

      full_client_dir       See class docstring above.

      director_repo_name    See class docstring above.

      vin                   See class docstring above.

      ecu_serial            See class docstring above.

      ecu_key               See class docstring above.

      timeserver_public_key See class docstring above.

      director_public_key   See class docstring above. (optional)

      partial_verifying     See class docstring above. (optional)

      time
        An initial time to set the Secondary's "clock" to, conforming to
        tuf.formats.ISO8601_DATETIME_SCHEMA.

      firmware_fileinfo (optional)
        See class docstring above. As provided here, this is the initial
        value, which will be provided in ECU Manifests generated for the
        Director's consumption until the firmware is updated.


    <Exceptions>

      tuf.FormatError
        if the arguments are not correctly formatted

      uptane.Error
        if arguments partial_verifying and director_public_key are inconsistent
          (partial_verifying True requires a director_public_key, and
           partial_verifying False requires no director_public_key)
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
    if director_public_key is not None:
        tuf.formats.ANYKEY_SCHEMA.check_match(director_public_key)

    self.director_repo_name = director_repo_name
    self.ecu_key = ecu_key
    self.vin = vin
    self.ecu_serial = ecu_serial
    self.full_client_dir = full_client_dir
    self.director_proxy = None
    self.timeserver_public_key = timeserver_public_key
    self.director_public_key = director_public_key
    self.partial_verifying = partial_verifying
    self.firmware_fileinfo = firmware_fileinfo

    if not self.partial_verifying and self.director_public_key is not None:
      raise uptane.Error('Secondary not set as partial verifying, but a director ' # TODO: Choose error class.
          'key was still provided. Full verification secondaries employ the '
          'normal TUF verifications rooted at root metadata files.')

    elif self.partial_verifying and self.director_public_key is None:
      raise uptane.Error('Secondary set as partial verifying, but a director '
          'key was not provided. Partial verification Secondaries validate '
          'only the ')


    # Create a TAP-4-compliant updater object. This will read pinned.json
    # and create single-repository updaters within it to handle connections to
    # each repository.
    self.updater = tuf.client.updater.Updater('updater')

    if director_repo_name not in self.updater.pinned_metadata['repositories']:
      raise uptane.Error('Given name for the Director repository is not a '
          'known repository, according to the pinned metadata from pinned.json')

    # We load the given time twice for simplicity in later code.
    self.all_valid_timeserver_times = [time, time]

    self.last_nonce_sent = None
    self.nonce_next = self._create_nonce()
    self.validated_targets_for_this_ecu = []





  def set_nonce_as_sent(self):
    """
    To be called when the ECU Version Manifest is submitted, as that
    includes the sending of this nonce.

    The most recent nonce sent (assigned here) is the nonce this Secondary
    expects to find in the next timeserver attestation it validates.
    """
    self.last_nonce_sent = self.nonce_next





  def change_nonce(self):
    """
    This should generally be called only by update_time.

    To be called only when this Secondary has validated a timeserver
    attestation that lists the current nonce, when we know that nonce has been
    used. Rolls over to a new nonce.

    The result in self.nonce_next is the nonce that should be used in any
    future message to the Primary. Once it has been sent to the Primary,
    set_nonce_as_sent should be called.
    """
    self.nonce_next = self._create_nonce()





  def _create_nonce(self):
    """
    Returns a pseudorandom number for use in protecting from replay attacks
    from the timeserver (or an intervening party).
    """
    return random.randint(
        uptane.formats.NONCE_LOWER_BOUND, uptane.formats.NONCE_UPPER_BOUND)





  def generate_signed_ecu_manifest(self, description_of_attacks_observed=''):
    """
    Returns a signed ECU manifest indicating self.firmware_fileinfo.

    If the optional description_of_attacks_observed argument is provided,
    the ECU Manifest will include that in the ECU Manifest (attacks_detected).
    """

    uptane.formats.DESCRIPTION_OF_ATTACKS_SCHEMA.check_match(
        description_of_attacks_observed)

    # We'll construct a signed signable_ecu_manifest_SCHEMA from the
    # targetinfo.
    # First, construct and check an ECU_VERSION_MANIFEST_SCHEMA.
    ecu_manifest = {
        'ecu_serial': self.ecu_serial,
        'installed_image': self.firmware_fileinfo,
        'timeserver_time': self.all_valid_timeserver_times[-1],
        'previous_timeserver_time': self.all_valid_timeserver_times[-2],
        'attacks_detected': description_of_attacks_observed
    }
    uptane.formats.ECU_VERSION_MANIFEST_SCHEMA.check_match(ecu_manifest)

    # Now we'll convert it into a signable object and sign it with a key we
    # generate.

    # Wrap the ECU version manifest object into an
    # uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA and check the format.
    # {
    #     'signed': ecu_version_manifest,
    #     'signatures': []
    # }
    signable_ecu_manifest = tuf.formats.make_signable(ecu_manifest)
    uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.check_match(
        signable_ecu_manifest)

    if tuf.conf.METADATA_FORMAT == 'der':
      der_signed_ecu_manifest = asn1_codec.convert_signed_metadata_to_der(
          signable_ecu_manifest, DATATYPE_ECU_MANIFEST, resign=True,
          private_key=self.ecu_key)
      # TODO: Consider verification of output here.
      return der_signed_ecu_manifest

    # Else use standard Python dictionary format specified in uptane.formats.

    # Now sign with that key.
    uptane.common.sign_signable(
        signable_ecu_manifest, [self.ecu_key], DATATYPE_ECU_MANIFEST)
    uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.check_match(
        signable_ecu_manifest)

    return signable_ecu_manifest





  def update_time(self, timeserver_attestation):
    """
    The function attemps to verify the time attestation from the Time Server,
    distributed to us by the Primary.
    If timeserver_attestation is correctly signed by the expected Timeserver
    key, and it lists the nonce we expected it to list (the one we last used
    in a request for the time), then this Secondary's time is updated.
    The new time will be used by this client (via TUF) in in place of system
    time when checking metadata for expiration.

    If the Secondary is using ASN.1/DER metadata, then timeserver_attestation
    is expected to be in that format, as a byte string.
    Otherwise, we're using simple Python dictionaries and timeserver_attestation
    conforms to uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.

    If verification is successful, switch to a new nonce for next time.
    """
    # If we're using ASN.1/DER format, convert the attestation into something
    # comprehensible (JSON-compatible dictionary) instead.
    if tuf.conf.METADATA_FORMAT == 'der':
      timeserver_attestation = asn1_codec.convert_signed_der_to_dersigned_json(
          timeserver_attestation, DATATYPE_TIME_ATTESTATION)

    # Check format.
    uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.check_match(
        timeserver_attestation)

    # Assume there's only one signature.
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


    # If the most recent nonce we sent is not in the timeserver attestation,
    # then we don't trust the timeserver attestation.
    if self.last_nonce_sent is None:
      # This ECU is fresh and hasn't actually ever sent a nonce to the Primary
      # yet. It would be impossible to validate a timeserver attestation.
      log.warning(YELLOW + 'Cannot verify a timeserver attestation yet: '
          'this fresh Secondary ECU has never communicated a nonce and ECU '
          'Version Manifest to the Primary.' + ENDCOLORS)
      return

    elif self.last_nonce_sent not in timeserver_attestation['signed']['nonces']:
      # TODO: Create a new class for this Exception in this file.
      raise uptane.BadTimeAttestation('Primary provided a time attestation '
          'that did not include any of the nonces this Secondary has sent '
          'recently. This Secondary cannot trust the time provided and will '
          'not register it. Because of the asynchrony in the Primary-Secondary '
          'communications, this can happen occasionally. If this occurs '
          'repeatedly for a sustained amount of time, it is possible that the '
          'Primary is compromised or that there is a Man in the Middle attack '
          'underway between the vehicle and the servers, or within the '
          'vehicle.')

    # Extract actual time from the timeserver's signed attestation.
    new_timeserver_time = timeserver_attestation['signed']['time']

    # Make sure the format is understandable to us before saving the
    # time.  Convert to a UNIX timestamp.
    new_timeserver_time_unix = int(tuf.formats.datetime_to_unix_timestamp(
        iso8601.parse_date(new_timeserver_time)))
    tuf.formats.UNIX_TIMESTAMP_SCHEMA.check_match(new_timeserver_time_unix)

    # Save verified time.
    self.all_valid_timeserver_times.append(new_timeserver_time)

    # Set the client's clock.  This will be used instead of system time by TUF.
    tuf.conf.CLOCK_OVERRIDE = new_timeserver_time_unix

    # Use a new nonce next time, since the nonce we were using has now been
    # used to successfully verify a timeserver attestation.
    self.change_nonce()





  def refresh_toplevel_metadata_from_repositories(self):
    """
    Refreshes client's metadata for the top-level roles:
      root, targets, snapshot, and timestamp

    See tuf.client.updater.Updater.refresh() for details, or the
    Uptane Implementation Specification, section 8.3.2 (Full Verification of
    Metadata).

    # TODO: This function is duplicated in primary.py and secondary.py. It must
    #       be moved to a general client.py as part of a fix to issue #14
    #       (github.com/uptane/uptane/issues/14).

    This can raise TUF update exceptions like
      - tuf.ExpiredMetadataError:
          if after attempts to update the Root metadata succeeded or failed,
          whatever currently trusted Root metadata we ended up with was expired.
      - tuf.NoWorkingMirrorError:
          if we could not obtain and verify all necessary metadata
    """

    # In order to provide Timeserver fast-forward attack protection, we do more
    # than simply calling updater.refresh().  Instead, we:
    #  1. Make note of the Timeserver key listed in the root metadata currently
    #     trusted by this client.
    #  2. Attempt updater.refresh()
    #  3. If refresh() failed (preferably only do this if it failed due to
    #     expired metadata), check to see if the Timeserver key listed in the
    #     root metadata NOW currently trusted is the same as before.  If it is
    #     not, reset the clock and try to refresh() one more time.
    #  4. Else if refresh() succeeded, check to see if the Timeserver key
    #     listed in the root metadata NOW currently trusted is the same as
    #     before.  If it is not, reset the clock.  Don't bother calling
    #     refresh() again, though.


    # Make note of the currently-trusted Timeserver key(s) and threshold.
    prior_timeserver_auth_info = self.updater.get_metadata(
        self.director_repo_name, 'current')['root']['roles']['Timeserver']

    # Refresh the Director first.  If the Director refresh fails, we check to
    # see if the Timeserver key has been rotated.
    try:
      self.updater.refresh(repo_name=self.director_repo_name)

    except (tuf.NoWorkingMirrorError, tuf.ExpiredMetadataError):
      # TODO: <~> In the except line above, see if it's sufficient to only
      #           catch NoWorkingMirrorError here.  (Do we ever get
      #           ExpiredMetadataError instead of NoWorkingMirrorError?
      #           Should we comb through the component errors in the
      #           NoWorkingMirrorErrors looking for ExpiredMetadataError?
      #           If so, write a function that returns True/False given the
      #           NoWorkingMirrorError, based on whether or not the failure was
      #           caused by ExpiredMetadataErrors.  Consider generalizing to
      #           return an error class if the NoWorkingMirrorError is caused
      #           solely by one error class, and something else if the causes
      #           are various.

      new_timeserver_auth_info = self.updater.get_metadata(
          self.director_repo_name, 'current')['root']['roles']['Timeserver']

      if prior_timeserver_auth_info != new_timeserver_auth_info:
        # TODO: Consider another, more invasive way to accomplish this (within
        #       root chain verification, after switch to theupdateframework/tuf)
        #       because there's a corner case here that isn't addressed:
        #       Suppose in root version X you change the Timeserver key after a
        #       fast-forward attack, then later in root version Y, change it
        #       back because you decide the key was not exposed or something....
        #       If a client goes from root version X-1 to root version Y within
        #       this update cycle (it would root chain within the refresh
        #       call), then we won't notice here that the key ever changed,
        #       and we won't resolve the fast-forward attack.  Detection should
        #       occur at a lower level, in every root chain link step.
        #       This will do for now, but fix the corner case by moving this
        #       check.
        self.update_timeserver_key_and_reset_clock(new_timeserver_auth_info)
        # Since we failed to update and the Timeserver key changed, we try to
        # refresh again, since we may have failed because of a fast-forward
        # attack.
        # Note that the only difference between this except clause and the
        # try-except-else's else clause below is that we refresh again here.
        self.updater.refresh()

      else:
        raise

    else:
      new_timeserver_auth_info = self.updater.get_metadata(
          self.director_repo_name, 'current')['root']['roles']['Timeserver']

      if prior_timeserver_auth_info != new_timeserver_auth_info:
        self.update_timeserver_key_and_reset_clock(new_timeserver_auth_info)


    # Now that we've dealt with the Director repository, deal with any and all
    # other repositories, presumably Image Repositories.
    for repository_name in self.updater.repositories:
      if repository_name == self.director_repo_name:
        continue

      self.updater.refresh(repo_name=repository_name)





  def update_timeserver_key_and_reset_clock(self, new_auth_info):
    '''
    Update the expected timeserver key, reset the clock to epoch, and discard
    old timeserver attestations.
    This function assumes that the timeserver key has changed.  (i.e. Do not
    call it if the key has not changed.))

    The argument new_auth_info is in the keyids+threshold format expected in
    the Root metadata, e.g.:
      {'keyids': ['1234...'], 'threshold': 1}
    This implementation supports only one Timeserver key.

    # TODO: This function is duplicated in primary.py and secondary.py. It must
    #       be moved to a general client.py as part of a fix to issue #14
    #       (github.com/uptane/uptane/issues/14).
    '''

    # TODO: Separate and migrate away from ROLE_SCHEMA.  ROLE_SCHEMA is poorly
    # named and used for too many distinct purposes.
    tuf.formats.ROLE_SCHEMA.check_match(new_auth_info)

    if len(new_auth_info['keyids']) != 1 or new_auth_info['threshold'] != 1:
      raise uptane.Error(
          'This implementation supports only a single key and threshold of '
          '1 for the Timeserver.  The given authentication information drawn '
          'from verified Root metadata does not match these constraints, '
          'listing ' + str(len(new_auth_info['keyids'])) + ' keys and having '
          'a threshold of ' + str(new_auth_info['threshold']) + '.')

    new_keyid = new_auth_info['keyids'][0]

    # We retrieve the key from tuf.keydb, using the keyid provided (obtained,
    # by the caller of this function, from the 'roles' section of the currently
    # trusted Director Root metadata.
    # We could instead fetch the key information directly from the 'keys'
    # section of the currently trusted Director Root metadata, looking it up
    # using the keyid from the 'roles' section like this:
    #    self.updater.get_metadata(self.director_repo_name, 'current')['root']['keys'][new_trusted_timeserver_keyid]
    # BUT we will instead use tuf.keydb.get_key().  keydb is fed the key
    # information when the metadata is verified. The difference is only that
    # certain implementations of general-purpose key rotation (TUF's TAP 8)
    # might result in these not matching, and the more trustworthy source being
    # tuf.keydb.  (At the time of this writing, TAP 8 is not implemented here.)
    # however, we do not fetch it directly, but request it from keydb, where
    # that information ends up when the metadata is updated.  There is a
    # possible edge case if general-purpose key rotation is implemented....
    self.timeserver_public_key = tuf.keydb.get_key(
        new_keyid, repository_name=self.director_repo_name)

    # Reset the clock to epoch and discard previously-trusted time attestations.
    tuf.conf.CLOCK_OVERRIDE = 0
    self.all_valid_timeserver_times = [tuf.formats.unix_timestamp_to_datetime(
        0).isoformat() + 'Z']
    self.all_valid_timeserver_attestations = []





  def fully_validate_metadata(self):
    """
    Treats the unvalidated metadata obtained from the Primary (which the
    Secondary does not fully trust) like a set of local TUF repositories,
    validating it against the older metadata this Secondary already has and
    already validated.

    All operations here are against the local files expected to be downloaded
    from the Primary, locations specified per pinned.json.

    Saves the validated, trustworthy target info as
    self.get_validated_target_info.

    Raises an exception if the role metadata itself cannot be validated. Does
    not raise an exception if some target file information indicated by the
    Director cannot be validated: instead, simply does not save that target
    file info as validated.


    For example, no exception is raised if:
      - All top-level role files are signed properly in each repository.
      - Target file A has custom fileinfo indicating the ECU Serial of the
        ECU for which it is intended, this ECU.

    Further, target info is saved for target A in
    self.validated_targets_for_this_ecu if Director and Image repositories
    indicate the same file info for targets A.

    If, target info would not be saved for target A if Director and Image
    repositories indicate different file info for target A.

    """

    # Refresh the top-level metadata first (all repositories).
    self.refresh_toplevel_metadata_from_repositories()

    validated_targets_for_this_ecu = []

    # Comb through the Director's direct instructions, picking out only the
    # target(s) earmarked for this ECU (by ECU Serial)
    for target in self.updater.targets_of_role(
        rolename='targets', repo_name=self.director_repo_name):

      # Ignore target info not marked as being for this ECU.
      if 'custom' not in target['fileinfo'] or \
          'ecu_serial' not in target['fileinfo']['custom'] or \
          self.ecu_serial != target['fileinfo']['custom']['ecu_serial']:
        continue

      # Fully validate the target info for our target(s).
      try:
        validated_targets_for_this_ecu.append(
            self.get_validated_target_info(target['filepath']))
      except tuf.UnknownTargetError:
        log.error(RED + 'Unable to validate target ' +
            repr(target['filepath']) + ', which the Director assigned to this '
            'Secondary ECU, using the validation rules in pinned.json' +
            ENDCOLORS)
        continue


    self.validated_targets_for_this_ecu = validated_targets_for_this_ecu





  def get_validated_target_info(self, target_filepath):
    """
    COPIED EXACTLY, MINUS COMMENTS, from primary.py.
    # TODO: Refactor later.
    Throws tuf.UnknownTargetError if unable to find/validate a target.
    """
    tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)

    validated_target_info = self.updater.target(
        target_filepath, multi_custom=True)

    if self.director_repo_name not in validated_target_info:

      raise tuf.Error('Unexpected behavior: did not receive target info from '
          'Director repository (' + repr(self.director_repo_name) + ') for '
          'a target (' + repr(target_filepath) + '). Is pinned.json configured '
          'to allow some targets to validate without Director approval, or is'
          'the wrong repository specified as the Director repository in the '
          'initialization of this primary object?')

    tuf.formats.TARGETFILE_SCHEMA.check_match(
        validated_target_info[self.director_repo_name])

    return validated_target_info[self.director_repo_name]





  def process_metadata(self, metadata_archive_fname):
    """
    Expand the metadata archive using _expand_metadata_archive()
    Validate metadata files using fully_validate_metadata()
    Select the Director targets.json file
    Pick out the target file(s) with our ECU serial listed
    Fully validate the metadata for the target file(s)
    """
    tuf.formats.RELPATH_SCHEMA.check_match(metadata_archive_fname)

    self._expand_metadata_archive(metadata_archive_fname)

    # This entails using the local metadata files as a repository.
    self.fully_validate_metadata()





  def _expand_metadata_archive(self, metadata_archive_fname):
    """
    Given the filename of an archive of metadata files validated and zipped by
    primary.py, unzip it into the contained metadata files, to be used as a
    local repository and validated by this Secondary.

    Note that attacks are possible against zip files. The particulars of the
    distribution of these metadata files from Primary to Secondary will vary
    greatly based on one's implementation and setup, so this is offered for
    instruction. The mechanism employed in particular should not obviate the
    protections provided by Uptane and TUF. It should time out rather than be
    susceptible to slow retrieval, and not introduce vulnerabilities in the
    face of a malicious Primary.
    """
    tuf.formats.RELPATH_SCHEMA.check_match(metadata_archive_fname)
    if not os.path.exists(metadata_archive_fname):
      raise uptane.Error('Indicated metadata archive does not exist. '
          'Filename: ' + repr(metadata_archive_fname))

    z = zipfile.ZipFile(metadata_archive_fname)

    z.extractall(os.path.join(self.full_client_dir, 'unverified'))





  def validate_image(self, image_fname):
    """
    Determines if the image with filename provided matches the expected file
    properties, based on the metadata we have previously validated (with
    fully_validate_metadata, stored in self.validated_targets_for_this_ecu). If
    this method completes without raising an exception, the image file is
    valid.

    <Arguments>

      image_fname
        This is the filename of the image file to validate. It is expected
        to match the filepath in the target file info (except without any
        leading '/' character). It should, therefore, not include any
        directory names except what is required to specify it within the
        target namespace.
        This file is expected to exist in the client directory
        (self.full_client_dir), in a subdirectory called 'unverified_targets'.

    <Exceptions>

      uptane.Error
        if the given filename does not match a filepath in the list of
        validated targets for this ECU (that is, the target(s) for which we
        have received validated instructions from the Director addressed to
        this ECU to install, and for which target info (file size and hashes)
        has been retrieved and fully validated)

      tuf.DownloadLengthMismatchError
        if the file does not have the expected length based on validated
        target info.

      tuf.BadHashError
        if the file does not have the expected hash based on validated target
        info

      tuf.FormatError
        if the given image_fname is not a path.

    <Returns>
      None.

    <Side-Effects>
      None.
    """
    tuf.formats.PATH_SCHEMA.check_match(image_fname)

    full_image_fname = os.path.join(
        self.full_client_dir, 'unverified_targets', image_fname)

    # Get target info by looking up fname (filepath).

    relevant_targetinfo = None

    for targetinfo in self.validated_targets_for_this_ecu:
      filepath = targetinfo['filepath']
      if filepath[0] == '/':
        filepath = filepath[1:]
      if filepath == image_fname:
        relevant_targetinfo = targetinfo

    if relevant_targetinfo is None:
      # TODO: Consider a more specific error class.
      raise uptane.Error('Unable to find validated target info for the given '
          'filename: ' + repr(image_fname) + '. Either metadata was not '
          'successfully updated, or the Primary is providing the wrong image '
          'file, or there was a very unlikely update to data on the Primary '
          'that had updated metadata but not yet updated images (The window '
          'for this is extremely small between two individually-atomic '
          'renames), or there has been a programming error....')


    # Check file length against trusted target info.
    with open(full_image_fname, 'rb') as fobj:
      tuf.client.updater.hard_check_file_length(
          fobj,
          relevant_targetinfo['fileinfo']['length'])

    # Check file hashes against trusted target info.
    with open(full_image_fname, 'rb') as fobj:
      tuf.client.updater.check_hashes(
          fobj, # FIX
          relevant_targetinfo['fileinfo']['hashes'],
          reset_fpointer=True) # Important for multiple hashes


    # If no error has been raised at this point, the image file is fully
    # validated and we can return.
    log.debug('Delivered target file has been fully validated: ' +
        repr(full_image_fname))

