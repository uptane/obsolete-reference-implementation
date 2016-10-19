"""
<Program Name>
  secondary.py

<Purpose>
  An Uptane client modeling the full behavior of a secondary ECU performing
  full metadata verification, as would be performed during ECU boot.
  Also includes some partial verification functionality.

"""

import uptane.formats
import tuf.formats
import uptane.ber_encoder as ber_encoder
from uptane.common import sign_signable

import xmlrpc.client
import uptane.director.director as director
import uptane.director.timeserver as timeserver

import os # For paths and makedirs
import shutil # For copyfile
import tuf.client.updater
import tuf.repository_tool as rt
import tuf.keys
import random # for nonces

class Secondary(object):

  """
  Fields:
    
    self.director_proxy:
      An xmlrpc proxy for the director server, used to submit manifests.

    self.updater:
      A tuf.client.updater.Updater object used to retrieve metadata and
      target files from the Director and Supplier repositories.

    self.client_dir:
      The directory in the working directory where all client data is stored
      for this secondary.

    self.timeserver_public_key:
      The key we expect the timeserver to use.

    self.partial_verifying:
      True if this instance is a partial verifier, False if it employs full
      metadata verification.

    self.director_public_key
      If this is a partial verification secondary, we store the key that we
      expect the Director to use here. Full verification clients should have
      None in this field.

    self.attacks_detected
      A string representing whatever attacks the secondary wishes to alert the
      Director about. Empty string indicates no alerts.

    # self.firmware_fileinfo:
    #     The image the ecu is currently using, identified by filename in the
    #     repo, hash of the file, and file sieze. This is an object matching
    #     tuf.formats.TARGETFILE_SCHEMA

    # self.nonce_next
    #   Next nonce the ECU will send to the Timeserver (via the Primary).

    # self.nonce_sent
    #   The last nonce the ECU sent to the Timeserver (via the Primary).


  """

  def __init__(self,
        client_dir,
        ecu_serial,
        timeserver_public_key=None,
        director_public_key=None,
        partial_verifying=False,
        vin='vin1111'):

    # Check arguments:
    tuf.formats.RELPATH_SCHEMA.check_match(client_dir)
    uptane.formats.VIN_SCHEMA.check_match(vin)
    uptane.formats.ECU_SERIAL_SCHEMA.check_match(ecu_serial)
    for key in [timeserver_public_key, director_public_key]:
      if key is not None:
        tuf.formats.ANYKEY_SCHEMA.check_match(key)

    self.vin = vin
    self.ecu_serial = ecu_serial
    self.client_dir = client_dir
    self.director_proxy = None
    self.most_recent_timeserver_time = None
    self.previous_timeserver_time = None
    self.timeserver_public_key = timeserver_public_key
    self.director_public_key = director_public_key
    self.partial_verifying = partial_verifying
    self.attacks_detected = ''

    if not self.partial_verifying and self.director_public_key is not None:
      raise Exception('Secondary not set as partial verifying, but a director ' # TODO: Choose error class.
          'key was still provided. Full verification secondaries employ the '
          'normal TUF verifications rooted at root metadata files.')

    #self.director_host = director.DIRECTOR_SERVER_HOST
    #self.director_port = director.DIRECTOR_SERVER_PORT

    WORKING_DIR = os.getcwd()
    CLIENT_DIR = os.path.join(WORKING_DIR, client_dir)
    CLIENT_METADATA_DIR_MAINREPO_CURRENT = os.path.join(CLIENT_DIR, 'metadata', 'mainrepo', 'current')
    CLIENT_METADATA_DIR_MAINREPO_PREVIOUS = os.path.join(CLIENT_DIR, 'metadata', 'mainrepo', 'previous')
    CLIENT_METADATA_DIR_DIRECTOR_CURRENT = os.path.join(CLIENT_DIR, 'metadata', 'director', 'current')
    CLIENT_METADATA_DIR_DIRECTOR_PREVIOUS = os.path.join(CLIENT_DIR, 'metadata', 'director', 'previous')

    # Note that the hosts and ports for the repositories are drawn from
    # pinned.json now. The services (timeserver and the director's
    # submit-manifest service) are still addressed here, though, currently
    # by pulling the constants from their modules directly
    # e.g. timeserver.TIMESERVER_PORT and director.DIRECTOR_SERVER_PORT).
    # Note that despite the vague name, the latter is not the director
    # repository, but a service that receives manifests.
    #MAIN_REPO_HOST = 'http://localhost'
    #MAIN_REPO_PORT = 30300
    #DIRECTOR_REPO_HOST = 'http://localhost'
    #DIRECTOR_REPO_PORT = 30301

    # We use these to fetch the root.json files for those repositories.
    MAIN_REPO_DIR = os.path.join(WORKING_DIR, 'repomain')
    #TARGETS_DIR = os.path.join(MAIN_REPO_DIR, 'targets')
    DIRECTOR_REPO_DIR = os.path.join(WORKING_DIR, 'repodirector')

    # Set up the TUF client directories for the two repositories.
    if os.path.exists(CLIENT_DIR):
      shutil.rmtree(CLIENT_DIR)

    for d in [
        CLIENT_METADATA_DIR_MAINREPO_CURRENT,
        CLIENT_METADATA_DIR_MAINREPO_PREVIOUS,
        CLIENT_METADATA_DIR_DIRECTOR_CURRENT,
        CLIENT_METADATA_DIR_DIRECTOR_PREVIOUS]:
      os.makedirs(d)

    # Get the root.json file from the mainrepo (would come with this client).
    shutil.copyfile(
        os.path.join(MAIN_REPO_DIR, 'metadata.staged', 'root.json'),
        os.path.join(CLIENT_METADATA_DIR_MAINREPO_CURRENT, 'root.json'))

    # Get the root.json file from the director repo (would come with this client).
    shutil.copyfile(
        os.path.join(DIRECTOR_REPO_DIR, 'metadata.staged', 'root.json'),
        os.path.join(CLIENT_METADATA_DIR_DIRECTOR_CURRENT, 'root.json'))

    # Add a pinned.json to this client (softlink it from a saved copy).
    os.symlink(
        os.path.join(WORKING_DIR, 'pinned.json'),
        os.path.join(CLIENT_DIR, 'metadata', 'pinned.json'))

    # Configure tuf with the client's metadata directories (where it stores the
    # metadata it has collected from each repository, in subdirectories).
    tuf.conf.repository_directory = CLIENT_DIR # This setting should probably be called client_directory instead, post-TAP4.

    # Create a TAP-4-compliant updater object. This will read pinning.json
    # and create single-repository updaters within it to handle connections to
    # each repository.
    self.updater = tuf.client.updater.Updater('updater')



  def refresh_toplevel_metadata_from_repositories(self):
    self.updater.refresh()




  def get_target_list_from_director(self):
    # TODO: <~> MUST FIX FOR PRODUCTION! Note that this assumes that the
    # director is conveying information to this secondary in its target role.
    # This is not something we can assume - director repo structure is not
    # required to be that flat.
    directed_targets = self.updater.targets_of_role(
        rolename='targets', repo_name='director')

    return directed_targets




  def get_validated_target_info(self, target_filepath):
    """
    Returns trustworthy target information for the given target file
    (specified by its file path). This information has been cleared according
    to the trust requirements of the pinning file (pinned.json) that this
    client is equipped with. In general, this means that the Director repository
    and the Supplier (mainrepo) repository have agreed on the file information
    (cryptographic hash and length).
    Raises tuf.UnknownTargetError if a given filepath is not listed by the
    consensus of Director and Supplier (or through whichever trusted path is
    specified by this client's pinned.json file.) If info is returned, it
    will match tuf.formats.TARGETFILE_SCHEMA and will have been validated by
    all required parties.
    """
    tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)
    return self.updater.target(target_filepath)




  # This is not part of the real design: when the primary steps in, it will
  # take over this functionality, and we will instead be sending this ecu
  # manifest to the Primary.
  def submit_ecu_manifest_to_director(self, signed_ecu_manifest):

    uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.check_match(
        signed_ecu_manifest)
    # TODO: <~> Be sure to update the previous line to indicate an ASN.1
    # version of the ecu_manifest after encoders have been implemented.


    server = xmlrpc.client.ServerProxy(
        'http://' + str(director.DIRECTOR_SERVER_HOST) + ':' +
        str(director.DIRECTOR_SERVER_PORT))
    #if not server.system.listMethods():
    #  raise Exception('Unable to connect to server.')

    server.submit_ecu_manifest(self.vin, self.ecu_serial, signed_ecu_manifest)




  def _create_nonce(self):
    """Returns a pseudorandom number for use in protecting from replay attacks
    from the timeserver (or an intervening party)."""
    return random.randint(
        uptane.formats.NONCE_LOWER_BOUND, uptane.formats.NONCE_UPPER_BOUND)



  # This function will be split between the Primary and Secondary once the
  # Primary is ready, and we will instead be retrieving this time from the
  # Primary.
  def update_time_from_timeserver(self, nonce):

    server = xmlrpc.client.ServerProxy(
        'http://' + str(timeserver.TIMESERVER_HOST) + ':' +
        str(timeserver.TIMESERVER_PORT))

    new_timeserver_attestation = server.get_signed_time([nonce]) # Primary

    # Check format.
    uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.check_match(
        new_timeserver_attestation)

    # Assume there's only one signature.
    assert len(new_timeserver_attestation['signatures']) == 1


    # TODO: <~> Check timeserver signature using self.timeserver_public_key!
    valid = tuf.keys.verify_signature(
        self.timeserver_public_key,
        new_timeserver_attestation['signatures'][0],
        new_timeserver_attestation['signed'])

    if not valid:
      raise tuf.BadSignatureError('Timeserver returned an invalid signature. '
          'Time is questionable. If you see this persistently, it is possible '
          'that the Primary is compromised.')

    if not nonce in new_timeserver_attestation['signed']['nonces']:
      # TODO: Determine whether or not to add something to self.attacks_detected
      # to indicate this problem. It's probably not certain enough? But perhaps
      # we should err on the side of reporting.
      # TODO: Create a new class for this Exception in this file.
      raise Exception('Timeserver returned a time attestation that did not '
          'include our nonce. This time is questionable. Report to Primary '
          'may have been missed. If you see this persistently, it is possible '
          'that the Primary or Timeserver is compromised.')


    # Extract actual time from the timeserver's signed attestation.
    new_timeserver_time = new_timeserver_attestation['signed']['time']

    # Rotate last recorded times and save new time.
    self.previous_timeserver_time = self.most_recent_timeserver_time
    self.most_recent_timeserver_time = new_timeserver_time



  def generate_signed_ecu_manifest(self, installed_firmware_targetinfo, keys):
    """
    Takes a tuf.formats.TARGETFILE_SCHEMA (the target info for the firmware on
    an ECU) and returns a signed ECU manifest indicating that target file info,
    encoded in BER (requires code added to two ber_* functions below).
    """

    import uptane.formats
    import tuf.repository_tool as rt

    # We'll construct a signed signable_ecu_manifest_SCHEMA from the
    # targetinfo.
    # First, construct and check an ECU_VERSION_MANIFEST_SCHEMA.
    ecu_manifest = {
        'ecu_serial': self.ecu_serial,
        'installed_image': installed_firmware_targetinfo,
        'timeserver_time': self.most_recent_timeserver_time,
        'previous_timeserver_time': self.previous_timeserver_time,
        'attacks_detected': self.attacks_detected
    }
    uptane.formats.ECU_VERSION_MANIFEST_SCHEMA.check_match(ecu_manifest)

    # Now we'll convert it into a signable object and sign it with a key we
    # generate.


    # TODO: Once the ber encoder functions are done, do this:
    original_ecu_manifest = ecu_manifest
    ecu_manifest = ber_encoder.ber_encode_ecu_manifest(ecu_manifest)

    # Wrap the ECU version manifest object into an
    # uptane.formats.signable_ecu_manifest and check the format.
    # {
    #     'signed': ecu_version_manifest,
    #     'signatures': []
    # }
    signable_ecu_manifest = tuf.formats.make_signable(
        ecu_manifest)
    uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.check_match(
        signable_ecu_manifest)

    # Now sign with that key. (Also do ber encoding of the signed portion.)
    signed_ecu_manifest = sign_signable(signable_ecu_manifest, keys)
    uptane.formats.SIGNABLE_ECU_VERSION_MANIFEST_SCHEMA.check_match(
        signed_ecu_manifest)

    # TODO: Once the ber encoder functions are done, do this:
    original_signed_ecu_manifest = signed_ecu_manifest
    ber_encoded_signed_ecu_manifest = ber_encoder.ber_encode_signable_object(
        signed_ecu_manifest)

    return ber_encoded_signed_ecu_manifest





  # def report_to_primary(self):
  #   """Sends version info to the Primary, along with a nonce for future
  #   timeserver requests."""
  #   nonce_to_use = self.create_nonce()

  #   self.nonce_sent = self.nonce_next
  #   self.nonce_next = self._create_nonce()
  #   # Consider saving some nonce history beyond just one position.

  #   # Additional data that may be sent to the primary:
  #   # Current time (perceived time? last timeserver call?)
  #   # Previous recorded time (to the extent this makes sense - previous timeserver time?)
  #   #
  #   raise NotImplementedError('Not yet written.')


  # def receive_updates_from_primary(self):
  #   """
  #   Listen for update data from the Primary and store it in extra storage to be
  #   checked and "installed" on next boot.

  #   Cycles forever.
  #   """

  #   while True:
  #     raise NotImplementedError('Not yet written.')

  #     sleep(0.05)

  # def validate_new_image(self):
  #   """
  #   Given file_info for a new image, validate it against signed metadata.
  #   """
  #   raise NotImplementedError('Not yet written.')