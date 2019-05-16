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

    # Create a TAP-4-compliant updater object. This will read pinned.json
    # and create single-repository updaters within it to handle connections to
    # each repository.
    self.updater = tuf.client.updater.Updater('updater')

    if director_repo_name not in self.updater.pinned_metadata['repositories']:
      raise uptane.Error('Given name for the Director repository is not a '
                         'known repository, according to the pinned metadata from pinned.json')
