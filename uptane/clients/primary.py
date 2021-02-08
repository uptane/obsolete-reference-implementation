"""
<Program Name>
  primary.py

<Purpose>
  Provides core functionality for Uptane Primary ECU clients:
  - Obtains and performs full verification of metadata and images, employing
    TUF (The Update Framework)
  - Prepares metadata and images for distribution to Secondaries
  - Receives ECU Manifests and holds them for the next Vehicle Manifest
  - Generates Vehicle Manifests
  - Receives nonces from Secondaries; maintains and cycles a list of nonces
    for use in requests for signed time from the Timeserver

  A detailed explanation of the role of the Primary in Uptane is available in
  the "Design Overview" and "Implementation Specification" documents, links to
  which are maintained at uptane.github.io
"""
from __future__ import unicode_literals

import uptane # Import before TUF modules; may change tuf.conf values.

from uptane.clients.client import Client

import os # For paths and makedirs
import shutil # For copyfile
import random # for nonces
import zipfile
import hashlib # if we're using DER encoding
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

from uptane import GREEN, RED, YELLOW, ENDCOLORS

# The following two imports are only used for the Uptane demonstration, where
# they enable delays and the display of splash banners indicating metadata
# rejection during sequential metadata checks. These should be pulled out of
# the reference implementation when possible.
import time
from demo.uptane_banners import *


log = uptane.logging.getLogger('primary')
log.addHandler(uptane.file_handler)
log.addHandler(uptane.console_handler)
log.setLevel(uptane.logging.DEBUG)



class Primary(Client):
  """
  <Purpose>
    This class contains the necessary code to perform Uptane validation of
    images and metadata, and core functionality supporting distribution of
    metadata and images to Secondary ECUs, combining ECU Manifests into a
    Vehicle Manifest and signing it, combining tokens for a Timeserver request,
    validating the response, etc.

  <Fields>

    self.vin
      A unique identifier for the vehicle that contains this Secondary ECU.
      In this reference implementation, this conforms to
      uptane.formats.VIN_SCHEMA. There is no need to use the vehicle's VIN in
      particular; we simply need a unique identifier for the vehicle, known
      to the Director.

    self.ecu_serial
      A unique identifier for this Primary ECU. In this reference
      implementation, this conforms to uptane.formats.ECU_SERIAL_SCHEMA.
      (In other implementations, the important point is that this should be
      unique.) The Director should be aware of this identifier.

    self.ecu_key
      The signing key for this Primary ECU. This key will be used to sign
      Vehicle Manifests that will then be sent to the Director). The Director
      should be aware of the corresponding public key, so that it can validate
      these Vehicle Manifests. Conforms to tuf.formats.ANYKEY_SCHEMA.

    self.full_client_dir
      The full path of the directory where all client data is stored for this
      Primary. This includes verified and unverified metadata and images and
      any temp files. Conforms to tuf.formats.PATH_SCHEMA.

    self.director_repo_name
      The name of the Director repository (e.g. 'director'), as listed in the
      map (or pinning) file (pinned.json). This value must appear in that file.
      Used to distinguish between the Image Repository and the Director
      Repository. Conforms to tuf.formats.REPOSITORY_NAME_SCHEMA.

    self.timeserver_public_key:
      The public key matching the private key that we expect the timeserver to
      use when signing attestations. Validation is against this key.

    self.ecu_manifests
      A dictionary containing the manifests provided by all ECUs. Will include
      all manifests sent by all ECUs. The Primary does not verify signatures on
      ECU manifests according to the Implementation Specification.
      Compromised ECUs may send bogus ECU manifests, so we simply send all
      manifests to the Director, who will sort through and discern what is
      going on.
      This is emptied every time the Primary produces a Vehicle Manifest
      (which will have included all of them). An implementer may wish to
      consider keeping these around until there is some likelihood that the
      Director has received them, as doing otherwise could deprive the
      Director of some historical and error/attack data. (Future ECU Manifests
      will provide current information, but useful diagnostic information may
      be lost.)

    self.my_secondaries:
      This is a list of all ECU Serials belonging to Secondaries of this
      Primary.

    self.assigned_targets:
      A dict mapping ECU Serial to the target file info that the Director has
      instructed that ECU to install.

    self.nonces_to_send:
      The list of nonces sent to us from Secondaries and not yet sent to the
      Timeserver.

    self.nonces_sent:
      The list of nonces sent to the Timeserver by our Secondaries, which we
      have already sent to the Timeserver. Will be checked against the
      Timeserver's response.

    self.distributable_full_metadata_archive_fname:
      The filename at which the full metadata archive is stored after each
      update cycle. Path is relative to uptane.WORKING_DIR. This is atomically
      moved into place (renamed) after it has been fully written, to avoid
      race conditions.

    self.distributable_partial_metadata_archive_fname:
      The filename at which the Director's targets metadata file is stored after
      each update cycle, once it is safe to use. This is atomically moved into
      place (renamed) after it has been fully written, to avoid race conditions.


  Methods organized by purpose: ("self" arguments excluded)

    High-level Methods for OEM/Supplier Primary code to use:
      __init__()
      primary_update_cycle()
      generate_signed_vehicle_manifest()
      get_nonces_to_send_and_rotate()
      save_distributable_metadata_files()
      update_time(timeserver_attestation)

    Lower-level methods called by primary_update_cycle() to perform retrieval
    and validation of metadata and data from central services:
      client->get_target_list_from_director()
      client->get_validated_target_info()

    Components of the interface available to a Secondary client:
      register_ecu_manifest(vin, ecu_serial, nonce, signed_ecu_manifest)
      get_last_timeserver_attestation()
      update_exists_for_ecu(ecu_serial)
      get_image_fname_for_ecu(ecu_serial)
      get_full_metadata_archive_fname()
      get_partial_metadata_archive_fname()
      register_new_secondary(ecu_serial)

    Private methods:
      _check_ecu_serial(ecu_serial)


  Use:
    import uptane.clients.primary as primary
    p = primary.Primary(
        full_client_dir='/Users/s/w/uptane/temp_primarymetadata',
        director_repo_name='director'
        vin='vin11111',
        ecu_serial='ecu00000',
        timeserver_public_key=<some key>)

    p.register_ecu_manifest(vin, ecu_serial, nonce, <a signed ECU manifest>)
    p.register_ecu_manifest(...)
    ...

    nonces = p.get_nonces_to_send_and_rotate()

    <submit the nonces to the Timeserver and save the returned time attestation>

    p.update_time(<the returned time attestation>)

    <metadata> = p.get_metadata_for_ecu(ecu_serial)
    <secondary firmware> = p.get_image_for_ecu(ecu_serial)
    <metadata> = p.get_metadata_for_ecu(<some other ecu serial>)
    ...

    And so on, with ECUs requesting images and metadata and registering ECU
    manifests (and providing nonces thereby).
  """

  def __init__(
    self,
    full_client_dir,  # '/Users/s/w/uptane/temp_primarymetadata'
    director_repo_name, # e.g. 'director'; value must appear in pinning file
    vin,              # 'vin11111'
    ecu_serial,       # 'ecu00000'
    ecu_key,
    time,
    timeserver_public_key,
    my_secondaries=None):

    """
    <Purpose>
      Constructor for class Primary

    <Arguments>

      full_client_dir       See class docstring above.

      director_repo_name    See class docstring above.

      vin                   See class docstring above.

      ecu_serial            See class docstring above.

      ecu_key               See class docstring above.

      timeserver_public_key See class docstring above.

      my_secondaries        See class docstring above. (optional)

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
    tuf.formats.REPOSITORY_NAME_SCHEMA.check_match(director_repo_name)
    tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(time)
    uptane.formats.VIN_SCHEMA.check_match(vin)
    uptane.formats.ECU_SERIAL_SCHEMA.check_match(ecu_serial)
    tuf.formats.ANYKEY_SCHEMA.check_match(timeserver_public_key)
    tuf.formats.ANYKEY_SCHEMA.check_match(ecu_key)
    # TODO: Should also check that ecu_key is a private key, not a
    # public key.

    super(Primary, self).__init__(full_client_dir, director_repo_name, vin,
                     ecu_serial, ecu_key, time, timeserver_public_key)


    self.my_secondaries = my_secondaries
    if self.my_secondaries is None:
      self.my_secondaries = [] # (because must not use mutable as default value)

    self.temp_full_metadata_archive_fname = os.path.join(
        full_client_dir, 'metadata', 'temp_full_metadata_archive.zip')
    self.distributable_full_metadata_archive_fname = os.path.join(
        full_client_dir, 'metadata', 'full_metadata_archive.zip')

    # TODO: Some of these assumptions are unseemly. Reconsider.
    self.temp_partial_metadata_archive_fname = os.path.join(
        full_client_dir, 'metadata', 'temp_partial_metadata_archive.zip')
    self.distributable_partial_metadata_archive_fname = os.path.join(
        full_client_dir, 'metadata', 'partial_metadata_archive.zip')

    # Initializations not directly related to arguments.
    self.nonces_to_send = []
    self.nonces_sent = []
    self.assigned_targets = dict()

    # Initialize the dictionary of manifests. This is a dictionary indexed
    # by ECU serial and with value being a list of manifests from that ECU, to
    # support the case in which multiple manifests have come from that ECU.
    self.ecu_manifests = {}





  def primary_update_cycle(self):
    """
    Download fresh metadata and images for this vehicle, as instructed by the
    Director and validated by the Image Repository.

    Begin by obtaining trustworthy target file metadata from the repositories,
    then instruct TUF to download matching files.

    Assign the target files to ECUs and keep that mapping in memory for
    later distribution.

    Package up the validated metadata into a zip archive for distribution.
    (Normally, we wouldn't want to include such details as packaging in the
    reference implementation, but in this case, it is the most convenient way
    to maintain the existing interfaces with TUF and with demonstration code.)


    <Exceptions>
      uptane.Error
        - If Director repo fails to include an ECU Serial in the custom metadata
          for a given target file.
        - If a file exists in the metadata directory in which validated files
          are deposited by TUF that does not have an extension that befits a
          file of type tuf.conf.METADATA_FORMAT.
    """

    # Get list of targets from the Director
    directed_targets = self.get_target_list_from_director()

    log.debug('Retrieving validated image file metadata from Image and '
        'Director Repositories.')

    # This next block employs get_validated_target_info calls to determine what
    # the right fileinfo (hash, length, etc) for each target file is. This
    # begins by matching paths/patterns in pinned.json to determine which
    # repository to connect to. Since pinned.json will generally assign all
    # targets to a multi-repository delegation requiring consensus between the
    # two repositories, one for the Director and one for the Image Repository,
    # this call will retrieve metadata from both repositories and compare it to
    # each other, and only return fileinfo if it can be retrieved from both
    # repositories and is identical (the metadata in the "custom" fileinfo
    # field need not match, and should not, since the Director will include
    # ECU IDs in this field, and the Image Repository cannot.

    # This will contain a list of tuf.formats.TARGETFILE_SCHEMA objects.
    verified_targets = []
    for targetinfo in directed_targets:
      target_filepath = targetinfo['filepath']
      try:
        # targetinfos = self.get_validated_target_info(target_filepath)
        # for repo in targetinfos:
        #   tuf.formats.TARGETFILE_SCHEMA.check_match(targetinfos[repo])
        verified_targets.append(self.get_validated_target_info(target_filepath))

      except tuf.UnknownTargetError:
        log.warning(RED + 'Director has instructed us to download a target (' +
            target_filepath + ') that is not validated by the combination of '
            'Image + Director Repositories. That update IS BEING SKIPPED. It '
            'may be that files have changed in the last few moments on the '
            'repositories. Try again, but if this happens often, you may be '
            'connecting to an untrustworthy Director, or there may be an '
            'untrustworthy Image Repository, or the Director and Image '
            'Repository may be out of sync.' + ENDCOLORS)

        # If running the demo, display splash banner indicating the rejection.
        # This clause should be pulled out of the reference implementation when
        # possible.
        if uptane.DEMO_MODE: # pragma: no cover
          print_banner(BANNER_DEFENDED, color=WHITE+DARK_BLUE_BG,
              text='The Director has instructed us to download a file that '
              'does not exactly match the Image Repository metadata. '
              'File: ' + repr(target_filepath), sound=TADA)
          time.sleep(3)


    # # Grab a filepath from each of the dicts of target file infos. (Each dict
    # # corresponds to one file, and the filepaths in all the infos in that dict
    # # will be the same - only the 'custom' field can differ within a given
    # # dict).
    # verified_target_filepaths = \
    #     [next(six.itervalues(targ))['filepath'] for targ in verified_targets]
    # get_validated_target_info() above returns only the Director's fileinfo,
    # and only after validating it fully as configured in pinned.json (i.e.
    # with the Image Repo or whatever other repository/ies specified in
    # pinned.json).
    verified_target_filepaths = [targ['filepath'] for targ in verified_targets]




    log.info('Metadata for the following Targets has been validated by both '
        'the Director and the Image repository. They will now be downloaded:' +
        repr(verified_target_filepaths))


    # For each target for which we have verified metadata:
    for target in verified_targets:

      tuf.formats.TARGETFILE_SCHEMA.check_match(target) # redundant, defensive

      if 'custom' not in target['fileinfo'] or \
          'ecu_serial' not in target['fileinfo']['custom']:
        raise uptane.Error('Director repo failed to include an ECU Serial for '
            'a target. Target metadata was: ' + repr(target))

      # Get the ECU Serial listed in the custom file data.
      assigned_ecu_serial = target['fileinfo']['custom']['ecu_serial']

      # Make sure it's actually an ECU we know about.
      if assigned_ecu_serial not in self.my_secondaries:
        log.warning(RED + 'Received a target from the Director with '
            'instruction to provide it to a Secondary ECU that is not known '
            'to this Primary! Disregarding / not downloading target or saving '
            'fileinfo!' + ENDCOLORS)
        continue

      # Save the target info as an update assigned to that ECU.
      self.assigned_targets[assigned_ecu_serial] = target


      # Make sure the resulting filename is actually in the client directory.
      # (In other words, enforce a jail.)
      # TODO: Do a proper review of this, and determine if it's necessary and
      # how to do it properly.
      full_targets_directory = os.path.abspath(os.path.join(
          self.full_client_dir, 'targets'))
      filepath = target['filepath']
      if filepath[0] == '/':
        filepath = filepath[1:]
      full_fname = os.path.join(full_targets_directory, filepath)
      enforce_jail(filepath, full_targets_directory)

      # Download each target.
      # Now that we have fileinfo for all targets listed by both the Director and
      # the Image Repository -- which should include file2.txt in this test --
      # we can download the target files and only keep each if it matches the
      # verified fileinfo. This call will try every mirror on every repository
      # within the appropriate delegation in pinned.json until one of them works.
      # In this case, both the Director and Image Repo are hosting the
      # file, just for my convenience in setup. If you remove the file from the
      # Director before calling this, it will still work (assuming Image Repo
      # still has it). (The second argument here is just where to put the
      # files.)
      try:
        self.updater.download_target(target, full_targets_directory)

      except tuf.NoWorkingMirrorError as e:
        error_report = ''
        for mirror in e.mirror_errors:
          error_report += \
              type(e.mirror_errors[mirror]).__name__ + ' from ' + mirror + '; '
        log.info(YELLOW + 'In downloading target ' + repr(filepath) +
            ', am unable to find a mirror providing a trustworthy file. '
            'Checking the mirrors resulted in these errors:  ' + error_report +
            ENDCOLORS)

        # If running the demo, display splash banner indicating the rejection.
        # This clause should be pulled out of the reference implementation when
        # possible.
        if uptane.DEMO_MODE: # pragma: no cover
          print_banner(BANNER_DEFENDED, color=WHITE+DARK_BLUE_BG,
              text='No image was found that exactly matches the signed metadata '
              'from the Director and Image Repositories. Not keeping '
              'untrustworthy files. ' + repr(target_filepath), sound=TADA)
          time.sleep(3)


        # # If this was our firmware, notify that we're not installing.
        # if filepath.startswith('/') and filepath[1:] == firmware_filename or \
        #   not filepath.startswith('/') and filepath == firmware_filename:

        log.info(YELLOW + 'The Director and Image Repository provided '
            'consistent metadata for new firmware, but contacted mirrors '
            'provided only untrustworthy images, which have been ' + GREEN +
            'rejected' + ENDCOLORS + ' Firmware not updated.')

      else:
        assert(os.path.exists(full_fname)), 'Programming error: no ' + \
            'download error, but file still does not exist.'
        log.info(GREEN + 'Successfully downloaded trustworthy ' +
            repr(filepath) + ' image.' + ENDCOLORS)


        # TODO: <~> There is an attack vector here, potentially, for a minor
        # attack, but it's pretty strange. Finish thinking through it with a
        # test case later. If the Director specifies two target files with the
        # same path (which shouldn't really be possible with TUF, but people
        # will be reimplementing things), the second one to be downloaded can
        # replace the first file, and then we may distribute that to both
        # Secondaries (which will still validate the files and catch the
        # mistake, but... we will still potentially have disrupted one of them
        # if it receives an update that wasn't right in the first place.... It
        # may perhaps end up in limp-home mode or something....)

        # In any case, there may also be race conditions. The point is that
        # we are storing a downloaded file and we are also, separately storing
        # the verified file info. Perhaps we should check the file against the
        # fileinfo at the last moment, before we send it on to the Secondary.
        # That should provide some prophylaxis?




    # Package the consistent and validated metadata we have now into two
    # locations for Secondaries that will request it.
    # For Full-Verification Secondaries, we keep an archive of all the valid
    # metadata, in a separate location that we only move (rename) files to
    # when we have validated all the files and have a self-consistent set.
    # For Partial-Verification Secondaries, we save just the Director's targets
    # metadata file in a separate location.


    # Copy the Director's targets file and then rapidly move it into place,
    # since requests for this file from Secondaries will arrive asynchronously.

    # Put the new metadata into place for distribution.
    # This entails archiving all metadata for full-metadata-verifying
    # Secondaries and copying just the Director's targets.json metadata file
    # for partial-verifying Secondaries. In both cases, the files are swapped
    # into place atomically after being constructed or copied. Secondaries
    # may be requesting these files live.
    self.save_distributable_metadata_files()





  def get_image_fname_for_ecu(self, ecu_serial):
    """
    Given an ECU serial, returns:
      - None if there is no image file to be distributed to that ECU
      - Else, a filename for the image file to distribute to that ECU
    """

    if not self.update_exists_for_ecu(ecu_serial):
      return None

    # Else, there is data to provide to the Secondary.

    # Get the full filename of the image file on disk.
    filepath = self.assigned_targets[ecu_serial]['filepath']
    if filepath[0] == '/': # Prune / at start. It's relative to the targets dir.
      filepath = filepath[1:]

    return os.path.join(self.full_client_dir, 'targets', filepath)





  def get_full_metadata_archive_fname(self):
    """
    Returns the absolute-path filename of an archive file (currently zip)
    containing all metadata from repositories necessary for a Full-Verification
    Secondary ECU to validate target files.

    The file is continuously available to asynchronous requests; it is
    replaced by atomic rename on POSIX-compliant systems, only once a new
    file is completely written. If this Primary has never completed an update
    cycle, it will not exist yet.

    Normally, for a reference implementation, it would be preferable to deal in
    the data itself, in memory, but for the time being, it is more convenient in
    maintaining the interfaces with TUF and demonstration code to do this with
    an archive file.
    """
    return self.distributable_full_metadata_archive_fname





  def get_partial_metadata_archive_fname(self):
    """
    Returns the absolute-path filename of the Director's targets.json metadata
    file, necessary for performing partial validation of target files (as a
    weak - "partial validation" - Secondary ECU would.

    The file is continuously available to asynchronous requests; it is
    replaced by atomic rename on POSIX-compliant systems, only once a new
    file is completely written. If this Primary has never completed an update
    cycle, it will not exist yet.
    """
    return self.distributable_partial_metadata_archive_fname





  def update_exists_for_ecu(self, ecu_serial):
    """
    Returns True if the Director has sent us instructions for the Secondary ECU
    specified, else returns False.

    <Exceptions>
      uptane.UnknownECU
        if the ecu_serial specified is not one known to this Primary (i.e. is
        not in self.my_secondaries).

      tuf.FormatError
        if ecu_serial does not match uptane.formats.ECU_SERIAL_SCHEMA

    <Side-effects>
      Ensures that ecu_serial has the right format.
    """

    uptane.formats.ECU_SERIAL_SCHEMA.check_match(ecu_serial)

    if ecu_serial not in self.my_secondaries:
      raise uptane.UnknownECU(
          'Received a request for an update for a Secondary ECU (' +
          repr(ecu_serial) + ') of which this Primary is not aware.')

    elif ecu_serial not in self.assigned_targets:
      log.info(
          'Received request for an update for a Secondary ECU (' +
          repr(ecu_serial) + ') for which this Primary has no update '
          'instructions from the Director.')
      return False

    else:
      return True






  def get_last_timeserver_attestation(self):
    """
    Returns the most recent validated timeserver attestation.
    If the Primary has never received a valid timeserver attestation, this
    returns None.
    """
    if not self.all_valid_timeserver_attestations:
      return None

    most_recent_attestation = self.all_valid_timeserver_attestations[-1]

    # We've been storing the time attestation as a simple JSON-compatible
    # dictionary. If the format of transfered metadata is expected to be
    # ASN.1/DER, we convert the time attestation back to DER and return it in
    # that form.
    if tuf.conf.METADATA_FORMAT == 'der':
      converted_attestation = asn1_codec.convert_signed_metadata_to_der(
          most_recent_attestation, DATATYPE_TIME_ATTESTATION)
      uptane.formats.DER_DATA_SCHEMA.check_match(converted_attestation)
      return converted_attestation

    elif tuf.conf.METADATA_FORMAT == 'json':
      uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.check_match(
          most_recent_attestation)
      return most_recent_attestation

    # An unrecognized value in the setting tuf.conf.METADATA_FORMAT should not
    # be allowed. This clause is provided so as to draw developer attention to
    # this location if a new metadata format has been added.
    else: # pragma: no cover
      raise uptane.Error('Unable to convert time attestation as configured. '
          'The settings supported for timeserver attestations are "json" and '
          '"der", but the value of tuf.conf.METADATA_FORMAT is: ' +
          repr(tuf.conf.METADATA_FORMAT))





  def generate_signed_vehicle_manifest(self):
    """
    Put ECU manifests into a vehicle manifest and sign it.
    Support multiple manifests from the same ECU.
    Output will comply with uptane.formats.VEHICLE_VERSION_MANIFEST_SCHEMA.
    """

    # Create the vv manifest:
    vehicle_manifest = {
        'vin': self.vin,
        'primary_ecu_serial': self.ecu_serial,
        'ecu_version_manifests': self.ecu_manifests
    }

    uptane.formats.VEHICLE_VERSION_MANIFEST_SCHEMA.check_match(vehicle_manifest)

    # Wrap the vehicle version manifest object into an
    # uptane.formats.SIGNABLE_VEHICLE_VERSION_MANIFEST_SCHEMA and check format.
    # {
    #     'signed': vehicle_manifest,
    #     'signatures': []
    # }
    signable_vehicle_manifest = tuf.formats.make_signable(vehicle_manifest)
    uptane.formats.SIGNABLE_VEHICLE_VERSION_MANIFEST_SCHEMA.check_match(
        signable_vehicle_manifest)

    if tuf.conf.METADATA_FORMAT == 'der':
      # Convert to DER and sign, replacing the Python dictionary.
      signable_vehicle_manifest = asn1_codec.convert_signed_metadata_to_der(
          signable_vehicle_manifest, DATATYPE_VEHICLE_MANIFEST,
          private_key=self.ecu_key, resign=True)

    else:
      # If we're not using ASN.1, sign the Python dictionary in a JSON encoding.
      uptane.common.sign_signable(
          signable_vehicle_manifest,
          [self.ecu_key],
          DATATYPE_VEHICLE_MANIFEST)

      uptane.formats.SIGNABLE_VEHICLE_VERSION_MANIFEST_SCHEMA.check_match(
          signable_vehicle_manifest)


    # Now that the ECU manifests have been incorporated into a vehicle manifest,
    # discard the ECU manifests.

    self.ecu_manifests = dict()

    return signable_vehicle_manifest





  def register_new_secondary(self, ecu_serial):
    """
    Currently called by Secondaries, but one would expect that this would happen
    through some other mechanism when a new Secondary ECU is installed in the
    vehicle.
    """
    uptane.formats.ECU_SERIAL_SCHEMA.check_match(ecu_serial)

    if ecu_serial in self.my_secondaries:
      log.info('ECU Serial ' + repr(ecu_serial) + ' already registered with '
          'this Primary.')
      return

    self.my_secondaries.append(ecu_serial)
    log.debug('ECU Serial ' + repr(ecu_serial) + ' has been registered as '
        'a Secondary with this Primary.')





  def _check_ecu_serial(self, ecu_serial):
    """
    Make sure the given ecu_serial is correctly formatted and known.

    <Exceptions>

      tuf.FormatError
        if the given ecu_serial is not of the correct format

      uptane.UnknownECU
        if the given ecu_serial is not registered with this Primary

    """
    # Check argument format.
    uptane.formats.ECU_SERIAL_SCHEMA.check_match(ecu_serial)

    if ecu_serial not in self.my_secondaries:
      raise uptane.UnknownECU("The given ECU is not in this Primary's list of "
          "known Secondary ECUs. Register the ECU with this Primary first.")




  def register_ecu_manifest(
      self, vin, ecu_serial, nonce, signed_ecu_manifest, force_pydict=False):
    """
    <Purpose>
      Called by Secondaries (in the demo, this is via an XMLRPC interface, or
      through another interface and passed through the XMLRPC interface).

      The Primary need not track ECU keys, so calling this doesn't result in a
      verification of the ECU's signature on the ECU manifest. This information
      is bundled together in a single vehicle report to the Director service.

    <Arguments>
      vin
          See class docstring above. The VIN of a Secondary in this vehicle
          submitting an ECU Manifest is expected to be the same as the VIN for
          this Primary. (In deployments where a Primary is shared -- for
          example, a dealer device connected directly to a vehicle for manual
          updates/modifications -- some code would have to be changed in a few
          modules to remove this assumption.)

      ecu_serial
          The ECU Serial of the Secondary submitting the ECU Manifest. This
          should match the ECU Serial listed in the signed manifest itself.

      nonce
          A (probably randomly generated) integer token produced by the
          Secondary, which this Primary is expected to include in a request to
          the Timeserver to produce a signed time that includes this token (and
          others). When the Secondary receives the signed timeserver
          attestation, if it sees this token in the signed contents of the
          attestation, the Secondary can be reassured of the freshness of the
          time attestation.

      signed_ecu_manifest
          The ECU Manifest a Secondary is submitting.

          The expected format that signed_ecu_manifest should conform to is
          based on the value of tuf.conf.METADATA_FORMAT:

            if 'json': uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA,
                       a JSON-compatible Python dictionary, the internal
                       repreentation of an ECU Manifest

            if 'der':  uptane.formats.DER_DATA_SCHEMA encoding data conforming
                       to ECUVersionManifest specified in file ECUModule.asn1
                       (and the Uptane Implementation Specification)

          See force_pydict.

      force_pydict (optional, default False)
          When True, the function treats signed_ecu_manifest as if the value of
          tuf.conf.METADATA_FORMAT is set to 'json'. See signed_ecu_manifest.

    <Exceptions>

      uptane.Spoofing
          if ecu_serial is not the same as the ECU Serial listed in the
          provided ECU Manifest itself.

      uptane.UnknownECU
          if ecu_serial is not one of this Primary's Secondaries

      uptane.UnknownVehicle
          if the VIN argument is not the same as this primary's VIN

      tuf.FormatError
          if any of the arguments are not in the expected formats.

    <Returns>
      None

    <Side Effects>
      self.ecu_manifests[ecu_serial] will contain signed_ecu_manifest
      nonce will be added to self.nonces_to_send

    """
    # Check argument format and that ECU Serial is registered
    self._check_ecu_serial(ecu_serial)
    tuf.formats.BOOLEAN_SCHEMA.check_match(force_pydict)
    uptane.formats.VIN_SCHEMA.check_match(vin)
    uptane.formats.NONCE_SCHEMA.check_match(nonce)


    if vin != self.vin:
      raise uptane.UnknownVehicle('Received an ECU Manifest supposedly hailing '
          'from a different vehicle....')

    if tuf.conf.METADATA_FORMAT == 'der' and not force_pydict:
      uptane.formats.DER_DATA_SCHEMA.check_match(signed_ecu_manifest)
      # If we're working with ASN.1/DER, convert it into the format specified in
      # uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.
      signed_ecu_manifest = asn1_codec.convert_signed_der_to_dersigned_json(
          signed_ecu_manifest, DATATYPE_ECU_MANIFEST)

    # Else, we're working with standard Python dictionaries and no conversion
    # is necessary, but we'll still validate the signed_ecu_manifest argument.
    else:
      uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.check_match(
          signed_ecu_manifest)

    if ecu_serial != signed_ecu_manifest['signed']['ecu_serial']:
      # TODO: Choose an exception class.
      raise uptane.Spoofing('Received a spoofed or mistaken manifest: supposed '
          'origin ECU (' + repr(ecu_serial) + ') is not the same as what is '
          'signed in the manifest itself (' +
          repr(signed_ecu_manifest['signed']['ecu_serial']) + ').')

    # If we haven't errored out above, then the format is correct, so save
    # the manifest to the Primary's dictionary of manifests.
    if ecu_serial in self.ecu_manifests:
      self.ecu_manifests[ecu_serial].append(signed_ecu_manifest)
    else:
      self.ecu_manifests[ecu_serial] = [signed_ecu_manifest]

    # And add the nonce the Secondary provided to the list of nonces to send
    # in the next Timeserver request.
    if nonce not in self.nonces_to_send:
      self.nonces_to_send.append(nonce)


    log.debug(GREEN + ' Primary received an ECU manifest from ECU ' +
        repr(ecu_serial) + ', along with nonce ' + repr(nonce) + ENDCOLORS)

    # Alert if there's been a detected attack.
    if signed_ecu_manifest['signed']['attacks_detected']:
      log.warning(YELLOW + ' Attacks have been reported by the Secondary! \n '
          'Attacks listed by ECU ' + repr(ecu_serial) + ':\n ' +
          signed_ecu_manifest['signed']['attacks_detected'] + ENDCOLORS)





  def get_nonces_to_send_and_rotate(self):
    """
    This should be called once when it is time to make a request for a signed
    attestation from the Timeserver.
    It:
     - returns the set of nonces to include in that request
     - registers those as sent (replaces self.nonces_sent with them)
     - empties self.nonces_to_send, to be populated from new messages from
       Secondaries.
    """
    self.nonces_sent = self.nonces_to_send
    self.nonces_to_send = []
    return self.nonces_sent





  def update_time(self, timeserver_attestation):
    """
    This should be called after get_nonces_to_send_and_rotate has been called
    and the nonces returned from that have been sent in a request for a time
    attestation from the Timeserver.

    The response from the Timeserver should then be provided to this function.
    This function attempts to verify the given attestation.
    If timeserver_attestation is correctly signed by the expected Timeserver
    key, and it lists all the nonces we expected it to list (those returned
    by the previous call to get_nonces_to_send_and_rotate), then the Primary's
    time is updated and the attestation will be saved so that it can be
    provided to Secondaries.  The new time will be used by this client (via
    TUF) in in place of system time when checking metadata for expiration.

    If the Primary is using ASN.1/DER metadata, then timeserver_attestation is
    expected to be in that format, as a byte string.
    Otherwise, we're using simple Python dictionaries and timeserver_attestation
    conforms to uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.
    """

    # Verify the signature of the timeserver on the attestation. If not verified,
    # it raises a BadSignatureError
    timeserver_attestation = self.verify_timeserver_signature(timeserver_attestation)

    for nonce in self.nonces_sent:
      if nonce not in timeserver_attestation['signed']['nonces']:
        # TODO: Determine whether or not to add something to self.attacks_detected
        # to indicate this problem. It's probably not certain enough? But perhaps
        # we should err on the side of reporting.
        # TODO: Create a new class for this Exception in this file.
        raise uptane.BadTimeAttestation('Timeserver returned a time attestation'
            ' that did not include one of the expected nonces. This time is '
            'questionable and will not be registered. If you see this '
            'persistently, it is possible that there is a Man in the Middle '
            'attack underway.')

    # Update the time of Primary with the time in attestation
    self.update_verified_time(timeserver_attestation)





  def save_distributable_metadata_files(self):
    """
    Generates two metadata files, all validated by this Primary, placing them
    in the expected locations available for distribution to Secondaries:

      - self.distributable_full_metadata_archive_fname
          a zip archive of all the metadata files, from all repositories,
          validated by this Primary, for use by Full Verification Secondaries.

      - self.distributable_partial_metadata_archive_fname
          the Director Targets role file alone, for use by Partial Verification
          Secondaries

    The particular method of distributing this metadata to Secondaries will
    vary greatly depending on one's setup, and is left to implementers, so the
    files are put in those locations and can be dealt with as desired by
    implementers' higher level Primary code. (Example in demo/demo_primary.py)

    The files here are each moved into place atomically to help avoid race
    conditions.
    """

    metadata_base_dir = os.path.join(self.full_client_dir, 'metadata')

    # Full Verification Metadata Preparation

    # Save a zipped version of all of the metadata.
    # Note that some stale metadata may be retained, but should never affect
    # security. Worth confirming.
    # What we want here, basically, is:
    #  <full_client_dir>/metadata/*/current/*.json or *.der
    with zipfile.ZipFile(self.temp_full_metadata_archive_fname, 'w') \
        as archive:
      # For each repository directory within the client metadata directory
      for repo_dir in os.listdir(metadata_base_dir):
        # Construct path to "current" metadata directory for that repository in
        # the client metadata directory, relative to Uptane working directory.
        abs_repo_dir = os.path.join(metadata_base_dir, repo_dir, 'current')
        if not os.path.isdir(abs_repo_dir):
          continue

        # Add each role metadata file to the archive.
        for role_fname in os.listdir(abs_repo_dir):
          # Reconstruct file path relative to Uptane working directory.
          role_abs_fname = os.path.join(abs_repo_dir, role_fname)

          # Make sure it's the right type of file. Should be a file, not a
          # directory. Symlinks are OK. Should end in an extension matching
          # tuf.conf.METADATA_FORMAT (presumably .json or .der, depending on
          # that setting).
          if not os.path.isfile(role_abs_fname) or not role_abs_fname.endswith(
              '.' + tuf.conf.METADATA_FORMAT):
            # Consider special error type.
            raise uptane.Error('Unexpected file type in a metadata '
                'directory: ' + repr(role_abs_fname) + ' Expecting only ' +
                tuf.conf.METADATA_FORMAT + 'files.')

          # Write the file to the archive, adjusting the path in the archive so
          # that when expanded, it resembles repository structure rather than
          # a client directory structure.
          archive.write(
              role_abs_fname,
              os.path.join(repo_dir, 'metadata', role_fname))


    # Partial Verification Metadata Preparation

    # Copy the Director's targets file to a temp location for partial-verifying
    # Secondaries.
    with zipfile.ZipFile(self.temp_partial_metadata_archive_fname, 'w') \
        as archive:

      # Need 'target' metadata from only director repo
      repo_name = self.director_repo_name
      # Construct path to "current" metadata directory for that repository in
      # the client metadata directory, relative to Uptane working directory.
      abs_repo_dir = os.path.join(metadata_base_dir, repo_name, 'current')

      # Archive only 'targets' metadat file for partial verification
      role_fname = 'targets.' + tuf.conf.METADATA_FORMAT
      # Reconstruct file path relative to Uptane working directory.
      role_abs_fname = os.path.join(abs_repo_dir, role_fname)

      # Make sure it's the right type of file. Should be a file, not a
      # directory. Symlinks are OK. Should end in an extension matching
      # tuf.conf.METADATA_FORMAT (presumably .json or .der, depending on
      # that setting).
      if not os.path.isfile(role_abs_fname) or not role_abs_fname.endswith(
          '.' + tuf.conf.METADATA_FORMAT):
        # Consider special error type.
        raise uptane.Error('Unexpected file type in a metadata '
            'directory: ' + repr(role_abs_fname) + ' Expecting only ' +
            tuf.conf.METADATA_FORMAT + 'files.')

      # Write the file to the archive, adjusting the path in the archive so
      # that when expanded, it resembles repository structure rather than
      # a client directory structure.
      archive.write(role_abs_fname,
                    os.path.join(repo_dir, 'metadata', role_fname))

    # Now move both Full and Partial metadata files into place. For each file,
    # this happens atomically on POSIX-compliant systems and replaces any
    # existing file.
    os.rename(
        self.temp_partial_metadata_archive_fname,
        self.distributable_partial_metadata_archive_fname)
    os.rename(
        self.temp_full_metadata_archive_fname,
        self.distributable_full_metadata_archive_fname)





def enforce_jail(fname, expected_containing_dir):
  """
  DO NOT ASSUME THAT THIS FUNCTION IS SECURE.
  """
  # Make sure it's in the expected directory.
  abs_fname = os.path.abspath(os.path.join(expected_containing_dir, fname))
  if not abs_fname.startswith(os.path.abspath(expected_containing_dir)):
    raise ValueError('Expected a filename in directory ' +
        repr(expected_containing_dir) + '. When appending ' + repr(fname) +
        ' to the given directory, the result was not in the given directory.')

  else:
    return abs_fname
