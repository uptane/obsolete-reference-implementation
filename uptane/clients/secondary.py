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

from uptane.clients.client import Client

import os # For paths and makedirs
import shutil # For copyfile
import random # for nonces
import zipfile # to expand the metadata archive retrieved from the Primary
import hashlib
import iso8601
import six

import tuf.formats
import tuf.keys
import tuf.keydb as key_database
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



class Secondary(Client):

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
      client->get_validated_target_info(target_filepath)
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

    super(Secondary, self).__init__(full_client_dir, director_repo_name, vin,
                     ecu_serial, ecu_key, time, timeserver_public_key)

    self.director_proxy = None
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


    # We load the given time twice for simplicity in later code.
    # TODO: Check if this is necessary.
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
    # Verify the signature of the timeserver on the attestation. If not verified,
    # it raises a BadSignatureError
    timeserver_attestation = self.verify_timeserver_signature(timeserver_attestation)

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

    # Update the time of Secondary with the time in attestation
    self.update_verified_time(timeserver_attestation)






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

    # Get list of targets from the Director
    directed_targets = self.get_target_list_from_director()

    validated_targets_for_this_ecu = []

    # Comb through the Director's direct instructions, picking out only the
    # target(s) earmarked for this ECU (by ECU Serial)
    for target in directed_targets:
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

    if validated_targets_for_this_ecu:
      self.validated_targets_for_this_ecu = validated_targets_for_this_ecu





  def partial_validate_metadata(self):
    """
    <Purpose>
      Given the filename of a file containing the Director's Targets role
      metadata, validates and processes that metadata, determining what firmware
      the Director has instructed this partial-verification Secondary ECU to
      install.
      The given metadata replaces this client's current Director metadata if
      the given metadata is valid -- i.e. if the metadata:
        - is signed by a key matching self.director_public_key
        - and is not expired (current date is before metadata's expiration date)
        - and does not have an older version number than this client has
          previously seen -- i.e. is not a rollback)
      Otherwise, an exception is raised indicating that the metadata is not
      valid.
      Further, if the metadata is valid, this function then updates
      self.validated_target_for_this_ecu if the metadata also lists a target
      for this ECU (i.e. includes a target with field "ecu_serial" set to this
      ECU's serial number)


    <Arguments>
      director_targets_metadata_fname
      Filename of the Director's Targets role metadata, in either JSON or
      ASN.1/DER format.


    <Returns>
      None


    <Exceptions>
      uptane.Error
        if director_targets_metadata_fname does not specify a file that exists
        or if tuf.conf.METADATA_FORMAT is somehow an unsupported format (i.e.
        not 'json' or 'der')
      tuf.BadSignatureError
        if the signature over the Targets metadata is not a valid
        signature by the key corresponding to self.director_public_key, or if
        the key type listed in the signature does not match the key type listed
        in the public key
      tuf.ExpiredMetadataError
        if the Targets metadata is expired
      tuf.ReplayedMetadataError
        if the Targets metadata has a lower version number than
        the last Targets metadata this client deemed valid (rollback)


    <Side-Effects>
      May update this client's metadata (Director Targets); see <Purpose>
      May update self.validated_targets_for_this_ecu; see <Purpose>
    """


    validated_targets_for_this_ecu = []

    upperbound_filelength = tuf.conf.DEFAULT_TARGETS_REQUIRED_LENGTH

    # Add director key in the key_database for metadata verification
    try:
      key_database.add_key(
          self.director_public_key, repository_name=self.director_repo_name)
    except tuf.KeyAlreadyExistsError:
      log.debug('Key already present in the key database')

    director_obj = self.updater.repositories['director']

    # _update_metadata carries out the verification of metadata
    # and then updates the metadata of the repository
    director_obj._update_metadata('targets', upperbound_filelength)

    # TODO: If this Targets metadata file indicates that
    #  the Timeserver key should be rotated then reset the
    #  clock used to determine the expiration of metadata
    #  to a minimal value.  It will be updated in the next cycle.

    # Is the metadata is not expired?
    director_obj._ensure_not_expired(director_obj.metadata['current']['targets'], 'targets')

    validated_targets_from_director = []
    # Do we have metadata for 'targets'?
    if 'targets' not in director_obj.metadata['current']:
      log.debug('No metadata for \'targtes\'. Unable to determine targets.')
      validated_targets_from_director = []

    # Get the targets specified by the role itself.
    for filepath, fileinfo in six.iteritems(director_obj.metadata['current']['targets']['targets']):
      new_target = {}
      new_target['filepath'] = filepath
      new_target['fileinfo'] = fileinfo

      validated_targets_from_director.append(new_target)

    for target in validated_targets_from_director:
      # Ignore target info not marked as being for this ECU.
      if 'custom' not in target['fileinfo'] or \
        'ecu_serial' not in target['fileinfo']['custom'] or \
        self.ecu_serial != target['fileinfo']['custom']['ecu_serial']:
        continue

      validated_targets_for_this_ecu.append(target)

    if validated_targets_from_director:
      self.validated_targets_for_this_ecu = validated_targets_for_this_ecu





  def process_metadata(self, metadata_archive_fname):
    """
    Runs either partial or full metadata verification, based on the
    value of self.partial_verifying.
    Note that in both cases, the use of files and archives is not key. Keep an
    eye on the procedure without regard to them. The central idea is to take
    the metadata pointed at by the argument here as untrusted and verify it
    using the full verification or partial verification algorithms from the
    Uptane Implementation Specification. It's generally expected that this
    metadata comes to the Secondary from the Primary, originally from the
    Director and Image repositories, but the way it gets here does not matter
    as long as it checks out as trustworthy.

    Full:
      The given filename, metadata_fname, should point to an archive of all
      metadata necessary to perform full verification, such as is produced by
      primary.save_distributable_metadata_files().
      process_metadata expands this archive to a local directory where
      repository files are expected to be found (the 'unverified' directory in
      directory self.full_client_dir).
      Then, these expanded metadata files are treated as repository metadata by
      the call to fully_validate_metadata(). The Director targets.json file is
      selected. The target file(s) with this Secondary's ECU serial listed is
      fully validated, using whatever provided metadata is necessary, by the
      underlying TUF code.

    Partial:
      The given filename, metadata_fname, should point to a single metadata
      role file, the Director's Targets role. The signature on the Targets role
      file is validated against the Director's public key
      (self.director_public_key). If the signature is valid, the new Targets
      role file is trusted, else it is discarded and we TUF raises a
      tuf.BadSignatureError.
      (Additional protections come from the Primary
      having vetted the file for us using full verification, as long as the
      Primary is trustworthy.)
      From the trusted Targets role file, the target with this Secondary's
      ECU identifier/serial listed is chosen, and the metadata describing that
      target (hash, length, etc.) is extracted from the metadata file and
      taken as the trustworthy description of the targets file to be installed
      on this Secondary.
    """

    tuf.formats.RELPATH_SCHEMA.check_match(metadata_archive_fname)

    self._expand_metadata_archive(metadata_archive_fname)

    # This verification entails using the local metadata files as a repository.
    if self.partial_verifying:
      self.partial_validate_metadata()
    else:
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

